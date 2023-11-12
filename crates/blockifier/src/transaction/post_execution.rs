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
pub enum PostExecutionFeeError {
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

/// Before fee transfer, need to check fee / resources used are valid.
/// This struct holds the result of this check: recommended fee to charge (useful in revert flow)
/// and an error if the check failed.
pub struct PostExecutionReport {
    recommended_fee: Fee,
    error: Option<PostExecutionFeeError>,
}

impl PostExecutionReport {
    /// Verifies the actual cost can be paid by the account. If not, reports an error and the fee
    /// that should be charged in revert flow.
    pub fn generate<S: StateReader>(
        state: &mut S,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
        cost_to_audit: &ActualCost,
        charge_fee: bool,
    ) -> TransactionExecutionResult<Self> {
        let passing_report = Self { recommended_fee: cost_to_audit.actual_fee, error: None };
        if !charge_fee || !account_tx_context.enforce_fee()? {
            return Ok(passing_report);
        }

        let ActualCost { actual_fee, actual_resources } = cost_to_audit;

        // First, compare the actual resources used against the upper bound(s) defined by the
        // sender.
        match account_tx_context {
            AccountTransactionContext::Current(context) => {
                // Check L1 gas limit.
                let max_l1_gas = context.l1_resource_bounds()?.max_amount as u128;
                let actual_used_l1_gas =
                    calculate_tx_l1_gas_usage(actual_resources, block_context)?;
                if actual_used_l1_gas > max_l1_gas {
                    return Ok(Self {
                        recommended_fee: get_fee_by_l1_gas_usage(
                            block_context,
                            max_l1_gas,
                            &account_tx_context.fee_type(),
                        ),
                        error: Some(PostExecutionFeeError::MaxL1GasAmountExceeded {
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
                    return Ok(Self {
                        recommended_fee: max_fee,
                        error: Some(PostExecutionFeeError::MaxFeeExceeded {
                            max_fee,
                            actual_fee: *actual_fee,
                        }),
                    });
                }
            }
        }

        // Initial check passed; verify against the account balance, which may have changed after
        // execution.
        let (balance_low, balance_high, can_pay) =
            get_balance_and_if_covers_fee(state, account_tx_context, block_context, *actual_fee)?;
        if can_pay {
            Ok(passing_report)
        } else {
            Ok(Self {
                recommended_fee: *actual_fee,
                error: Some(PostExecutionFeeError::InsufficientFeeTokenBalance {
                    fee: *actual_fee,
                    balance_low,
                    balance_high,
                }),
            })
        }
    }

    pub fn recommended_fee(&self) -> Fee {
        self.recommended_fee
    }

    pub fn error(&self) -> Option<PostExecutionFeeError> {
        self.error.clone()
    }
}
