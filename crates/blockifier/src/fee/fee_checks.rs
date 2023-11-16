use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;
use thiserror::Error;

use crate::block_context::BlockContext;
use crate::fee::actual_cost::ActualCost;
use crate::fee::fee_utils::{
    calculate_tx_l1_gas_usage, get_balance_and_if_covers_fee, get_fee_by_l1_gas_usage,
};
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{AccountTransactionContext, FeeType, TransactionExecutionResult};

#[derive(Clone, Copy, Debug, Error)]
pub enum FeeCheckError {
    #[error("Insufficient max L1 gas: max amount: {max_amount}, actual used: {actual_amount}.")]
    MaxL1GasAmountExceeded { max_amount: u128, actual_amount: u128 },
    #[error("Insufficient max fee: max fee: {max_fee:?}, actual fee: {actual_fee:?}")]
    MaxFeeExceeded { max_fee: Fee, actual_fee: Fee },
    #[error(
        "Insufficient fee token balance. Fee: {fee:?}, balance: low/high \
         {balance_low:?}/{balance_high:?}."
    )]
    InsufficientFeeTokenBalance { fee: Fee, balance_low: StarkFelt, balance_high: StarkFelt },
}

/// This struct holds the result of fee checks: recommended fee to charge (useful in post-execution
/// revert flow) and an error if the check failed.
struct FeeCheckReport {
    recommended_fee: Fee,
    error: Option<FeeCheckError>,
}

pub trait FeeCheckReportFields {
    fn recommended_fee(&self) -> Fee;
    fn error(&self) -> Option<FeeCheckError>;
}

impl FeeCheckReportFields for FeeCheckReport {
    fn recommended_fee(&self) -> Fee {
        self.recommended_fee
    }

    fn error(&self) -> Option<FeeCheckError> {
        self.error
    }
}

impl FeeCheckReport {
    pub fn success_report(actual_fee: Fee) -> Self {
        Self { recommended_fee: actual_fee, error: None }
    }

    /// Given a fee error and the current context, constructs and returns a report.
    pub fn from_fee_check_error(
        actual_fee: Fee,
        error: FeeCheckError,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> TransactionExecutionResult<Self> {
        let recommended_fee = match error {
            // If the error is insufficient balance, the recommended fee is the actual fee.
            // This recommendation assumes (a) the pre-validation checks were applied and pass (i.e.
            // the sender initially could cover the resource bounds), and (b) the actual resources
            // are within the resource bounds set by the sender.
            FeeCheckError::InsufficientFeeTokenBalance { .. } => actual_fee,
            // If the error is resource overdraft, the recommended fee is the resource bounds.
            // If the transaction passed pre-validation checks (i.e. balance initially covered the
            // resource bounds), the sender should be able to pay this fee.
            FeeCheckError::MaxFeeExceeded { .. } | FeeCheckError::MaxL1GasAmountExceeded { .. } => {
                match account_tx_context {
                    AccountTransactionContext::Current(context) => get_fee_by_l1_gas_usage(
                        block_context,
                        context.l1_resource_bounds()?.max_amount as u128,
                        &FeeType::Strk,
                    ),
                    AccountTransactionContext::Deprecated(context) => context.max_fee,
                }
            }
        };
        Ok(Self { recommended_fee, error: Some(error) })
    }

    /// If the actual cost exceeds the resource bounds on the transaction, returns a fee check
    /// error.
    fn check_actual_cost_within_bounds(
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        let ActualCost { actual_fee, actual_resources } = actual_cost;

        // First, compare the actual resources used against the upper bound(s) defined by the
        // sender.
        match account_tx_context {
            AccountTransactionContext::Current(context) => {
                // Check L1 gas limit.
                let max_l1_gas = context.l1_resource_bounds()?.max_amount as u128;
                let actual_used_l1_gas =
                    calculate_tx_l1_gas_usage(actual_resources, block_context)?;
                if actual_used_l1_gas > max_l1_gas {
                    return Err(FeeCheckError::MaxL1GasAmountExceeded {
                        max_amount: max_l1_gas,
                        actual_amount: actual_used_l1_gas,
                    })?;
                }
            }
            AccountTransactionContext::Deprecated(context) => {
                // Check max fee.
                let max_fee = context.max_fee;
                if actual_fee > &max_fee {
                    return Err(FeeCheckError::MaxFeeExceeded {
                        max_fee,
                        actual_fee: *actual_fee,
                    })?;
                }
            }
        }

        Ok(())
    }

    /// If the actual cost exceeds the sender's balance, returns a fee check error.
    fn check_can_pay_fee<S: StateReader>(
        state: &mut S,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        let ActualCost { actual_fee, .. } = actual_cost;
        let (balance_low, balance_high, can_pay) =
            get_balance_and_if_covers_fee(state, account_tx_context, block_context, *actual_fee)?;
        if can_pay {
            return Ok(());
        }
        Err(FeeCheckError::InsufficientFeeTokenBalance {
            fee: *actual_fee,
            balance_low,
            balance_high,
        })?
    }
}

macro_rules! impl_report_fields {
    ($report_type:ty) => {
        impl FeeCheckReportFields for $report_type {
            fn recommended_fee(&self) -> Fee {
                self.0.recommended_fee()
            }

            fn error(&self) -> Option<FeeCheckError> {
                self.0.error()
            }
        }
    };
}

pub struct PostValidationReport(FeeCheckReport);
pub struct PostExecutionReport(FeeCheckReport);

impl_report_fields!(PostValidationReport);
impl_report_fields!(PostExecutionReport);

impl PostValidationReport {
    /// Verifies that the actual cost of validation is within sender bounds.
    /// Note: the balance cannot be changed in `__validate__` (which cannot call other contracts),
    /// so there is no need to recheck that balance >= actual_cost.
    pub fn verify(
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
    ) -> TransactionExecutionResult<()> {
        // If fee is not enforced, no need to check post-execution.
        if !account_tx_context.enforce_fee()? {
            return Ok(());
        }

        FeeCheckReport::check_actual_cost_within_bounds(
            block_context,
            account_tx_context,
            actual_cost,
        )
    }
}

impl PostExecutionReport {
    /// Verifies the actual cost can be paid by the account. If not, reports an error and the fee
    /// that should be charged in revert flow.
    pub fn new<S: StateReader>(
        state: &mut S,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        actual_cost: &ActualCost,
        charge_fee: bool,
    ) -> TransactionExecutionResult<Self> {
        let ActualCost { actual_fee, .. } = actual_cost;

        // If fee is not enforced, no need to check post-execution.
        if !charge_fee || !account_tx_context.enforce_fee()? {
            return Ok(Self(FeeCheckReport::success_report(*actual_fee)));
        }

        // First, compare the actual resources used against the upper bound(s) defined by the
        // sender.
        let cost_with_bounds_result = FeeCheckReport::check_actual_cost_within_bounds(
            block_context,
            account_tx_context,
            actual_cost,
        );

        // Next, verify the actual cost is covered by the account balance, which may have changed
        // after execution. If the above check passes, the pre-execution balance covers the actual
        // cost for sure.
        let can_pay_fee_result = FeeCheckReport::check_can_pay_fee(
            state,
            block_context,
            account_tx_context,
            actual_cost,
        );

        for fee_check_result in [cost_with_bounds_result, can_pay_fee_result] {
            match fee_check_result {
                Ok(_) => continue,
                Err(TransactionExecutionError::FeeCheckError(fee_check_error)) => {
                    // Found an error; set the recommended fee based on the error variant and
                    // current context, and return the report.
                    return Ok(Self(FeeCheckReport::from_fee_check_error(
                        *actual_fee,
                        fee_check_error,
                        block_context,
                        account_tx_context,
                    )?));
                }
                Err(other_error) => return Err(other_error),
            }
        }

        Ok(Self(FeeCheckReport::success_report(actual_cost.actual_fee)))
    }
}
