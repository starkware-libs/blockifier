use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;
use thiserror::Error;

use crate::block_context::BlockContext;
use crate::fee::actual_cost::ActualCost;
use crate::fee::fee_utils::{
    calculate_tx_l1_gas_usage, get_balance_and_if_covers_fee, get_fee_by_l1_gas_usage,
};
use crate::state::state_api::StateReader;
use crate::transaction::objects::{
    AccountTransactionContext, HasRelatedFeeType, TransactionExecutionResult,
};

#[derive(Clone, Debug, Error)]
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
    post_execution_recommended_fee: Fee,
    error: Option<FeeCheckError>,
}

pub trait FeeCheckReportFields {
    fn post_execution_recommended_fee(&self) -> Fee;
    fn error(&self) -> Option<FeeCheckError>;
}

impl FeeCheckReportFields for FeeCheckReport {
    fn post_execution_recommended_fee(&self) -> Fee {
        self.post_execution_recommended_fee
    }

    fn error(&self) -> Option<FeeCheckError> {
        self.error.clone()
    }
}

impl FeeCheckReport {
    pub fn passing_report(actual_fee: Fee) -> Self {
        Self { post_execution_recommended_fee: actual_fee, error: None }
    }
}

/// If the actual cost exceeds the resource bounds on the transaction, returns a report with an
/// error and a post-execution fee recommendation.
fn check_actual_cost_within_bounds(
    block_context: &BlockContext,
    account_tx_context: &AccountTransactionContext,
    actual_cost: &ActualCost,
) -> TransactionExecutionResult<FeeCheckReport> {
    let ActualCost { actual_fee, actual_resources } = actual_cost;

    // First, compare the actual resources used against the upper bound(s) defined by the
    // sender.
    match account_tx_context {
        AccountTransactionContext::Current(context) => {
            // Check L1 gas limit.
            let max_l1_gas = context.l1_resource_bounds()?.max_amount as u128;
            let actual_used_l1_gas = calculate_tx_l1_gas_usage(actual_resources, block_context)?;
            if actual_used_l1_gas > max_l1_gas {
                return Ok(FeeCheckReport {
                    post_execution_recommended_fee: get_fee_by_l1_gas_usage(
                        block_context,
                        max_l1_gas,
                        &account_tx_context.fee_type(),
                    ),
                    error: Some(FeeCheckError::MaxL1GasAmountExceeded {
                        max_amount: max_l1_gas,
                        actual_amount: actual_used_l1_gas,
                    }),
                });
            }
        }
        AccountTransactionContext::Deprecated(context) => {
            // Check max fee.
            let max_fee = context.max_fee;
            if actual_fee > &max_fee {
                return Ok(FeeCheckReport {
                    post_execution_recommended_fee: max_fee,
                    error: Some(FeeCheckError::MaxFeeExceeded { max_fee, actual_fee: *actual_fee }),
                });
            }
        }
    }

    Ok(FeeCheckReport::passing_report(*actual_fee))
}

/// If the actual cost exceeds the sender's balance, returns a report with an error and a
/// post-execution fee recommendation.
fn check_can_pay_fee<S: StateReader>(
    state: &mut S,
    block_context: &BlockContext,
    account_tx_context: &AccountTransactionContext,
    actual_cost: &ActualCost,
) -> TransactionExecutionResult<FeeCheckReport> {
    let ActualCost { actual_fee, .. } = actual_cost;
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, account_tx_context, block_context, *actual_fee)?;
    if can_pay {
        return Ok(FeeCheckReport::passing_report(*actual_fee));
    }
    Ok(FeeCheckReport {
        post_execution_recommended_fee: *actual_fee,
        error: Some(FeeCheckError::InsufficientFeeTokenBalance {
            fee: *actual_fee,
            balance_low,
            balance_high,
        }),
    })
}

pub struct PostExecutionReport(FeeCheckReport);

impl FeeCheckReportFields for PostExecutionReport {
    fn post_execution_recommended_fee(&self) -> Fee {
        self.0.post_execution_recommended_fee()
    }

    fn error(&self) -> Option<FeeCheckError> {
        self.0.error()
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
            return Ok(Self(FeeCheckReport::passing_report(*actual_fee)));
        }

        // First, compare the actual resources used against the upper bound(s) defined by the
        // sender.
        let resource_bounds_report =
            check_actual_cost_within_bounds(block_context, account_tx_context, actual_cost)?;
        if resource_bounds_report.error().is_some() {
            return Ok(Self(resource_bounds_report));
        }

        // Initial check passed; resource bounds cover the actual cost, and are covered by
        // pre-execution balance (verified in pre-validation phase).
        // Verify against the account balance, which may have changed after execution.
        Ok(Self(check_can_pay_fee(state, block_context, account_tx_context, actual_cost)?))
    }
}
