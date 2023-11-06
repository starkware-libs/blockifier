use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;
use thiserror::Error;

use super::fee_utils::{calculate_tx_l1_gas_usage, get_fee_by_l1_gas_usage};
use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::execution::entry_point::ExecutionResources;
use crate::fee::fee_utils::get_balance_and_if_covers_fee;
use crate::state::cached_state::{CachedState, StateChanges, StateChangesCount};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::objects::{
    AccountTransactionContext, HasRelatedFeeType, ResourcesMapping, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::{calculate_l1_gas_usage, calculate_tx_resources};

#[derive(Debug, Error)]
pub enum PostExecutionAuditorError {
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

// TODO(Gilad): Use everywhere instead of passing the `actual_{fee,resources}` tuple, which often
// get passed around together.
pub struct ActualCost {
    pub actual_fee: Fee,
    pub actual_resources: ResourcesMapping,
}

impl ActualCost {
    pub fn builder_for_l1_handler(
        block_context: &BlockContext,
        tx_context: AccountTransactionContext,
        l1_handler_payload_size: usize,
    ) -> ActualCostBuilder<'_> {
        ActualCostBuilder::new(block_context, tx_context, TransactionType::L1Handler)
            .without_sender_address()
            .with_l1_payload_size(l1_handler_payload_size)
    }
}

#[derive(Debug, Clone)]
// Invariant: private fields initialized after `new` is called via dedicated methods.
pub struct ActualCostBuilder<'a> {
    pub account_tx_context: AccountTransactionContext,
    pub tx_type: TransactionType,
    pub block_context: BlockContext,
    validate_call_info: Option<&'a CallInfo>,
    execute_call_info: Option<&'a CallInfo>,
    state_changes: StateChanges,
    sender_address: Option<ContractAddress>,
    l1_payload_size: Option<usize>,
    n_reverted_steps: usize,
}

impl<'a> ActualCostBuilder<'a> {
    // Recommendation: use constructor from account transaction, or from actual cost, to build this.
    pub fn new(
        block_context: &BlockContext,
        account_tx_context: AccountTransactionContext,
        tx_type: TransactionType,
    ) -> Self {
        Self {
            block_context: block_context.clone(),
            sender_address: Some(account_tx_context.sender_address()),
            account_tx_context,
            tx_type,
            validate_call_info: None,
            execute_call_info: None,
            state_changes: StateChanges::default(),
            l1_payload_size: None,
            n_reverted_steps: 0,
        }
    }

    pub fn without_sender_address(mut self) -> Self {
        self.sender_address = None;
        self
    }

    // Call the `build` method to construct the actual cost object, after feeding the builder
    // using the setters below.
    pub fn build(
        self,
        execution_resources: &ExecutionResources,
    ) -> TransactionExecutionResult<ActualCost> {
        self.calculate_actual_fee_and_resources(execution_resources, self.n_reverted_steps)
    }

    // Setters.

    pub fn with_validate_call_info(mut self, validate_call_info: &'a Option<CallInfo>) -> Self {
        self.validate_call_info = validate_call_info.as_ref();
        self
    }

    pub fn with_execute_call_info(mut self, execute_call_info: &'a Option<CallInfo>) -> Self {
        self.execute_call_info = execute_call_info.as_ref();
        self
    }

    pub fn try_add_state_changes(
        mut self,
        state: &mut CachedState<impl StateReader>,
    ) -> StateResult<Self> {
        let fee_token_address =
            self.block_context.fee_token_address(&self.account_tx_context.fee_type());

        let new_state_changes = state
            .get_actual_state_changes_for_fee_charge(fee_token_address, self.sender_address)?;
        self.state_changes = StateChanges::merge(vec![self.state_changes, new_state_changes]);
        Ok(self)
    }

    pub fn with_l1_payload_size(mut self, l1_payload_size: usize) -> Self {
        self.l1_payload_size = Some(l1_payload_size);
        self
    }

    pub fn with_reverted_steps(mut self, n_reverted_steps: usize) -> Self {
        self.n_reverted_steps = n_reverted_steps;
        self
    }

    // Private methods.

    // Construct the actual cost object using all fields that were set in the builder.
    fn calculate_actual_fee_and_resources(
        &self,
        execution_resources: &ExecutionResources,
        n_reverted_steps: usize,
    ) -> TransactionExecutionResult<ActualCost> {
        let state_changes_count = StateChangesCount::from(&self.state_changes);
        let non_optional_call_infos = vec![self.validate_call_info, self.execute_call_info]
            .into_iter()
            .flatten()
            .collect::<Vec<&CallInfo>>();
        let l1_gas_usage = calculate_l1_gas_usage(
            &non_optional_call_infos,
            state_changes_count,
            self.l1_payload_size,
        )?;
        let mut actual_resources =
            calculate_tx_resources(execution_resources, l1_gas_usage, self.tx_type)?;

        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            n_reverted_steps;

        let actual_fee = if self.account_tx_context.enforce_fee() {
            self.account_tx_context.calculate_tx_fee(&actual_resources, &self.block_context)?
        } else {
            Fee(0)
        };

        Ok(ActualCost { actual_fee, actual_resources })
    }
}

pub struct PostExecutionAuditor<'a> {
    pub block_context: &'a BlockContext,
    pub account_tx_context: &'a AccountTransactionContext,
    pub actual_cost: &'a ActualCost,
    pub charge_fee: bool,
}

impl PostExecutionAuditor<'_> {
    // Utility to check the actual cost can be paid by the account. If not, returns an error.
    pub fn verify_valid_actual_cost<S: StateReader>(
        &self,
        state: &mut S,
    ) -> TransactionExecutionResult<()> {
        if !self.charge_fee {
            return Ok(());
        }

        let ActualCost { actual_fee: post_execute_fee, actual_resources: post_execute_resources } =
            &self.actual_cost;

        // First, compare actual resources used against the upper bound(s) defined by the sender.
        // If the initial check fails, revert and charge based on the upper bound(s) and current
        // price(s). The resources reported in the error
        // The sender is ensured to have sufficient balance to cover these costs due to
        // pre-validation checks.
        match self.account_tx_context {
            AccountTransactionContext::Current(context) => {
                // Check L1 gas limit. If overshot, revert and charge for the L1 gas limit.
                let max_l1_gas =
                    context.l1_resource_bounds().expect("L1 gas bounds must be set.").max_amount
                        as u128;
                let actual_used_l1_gas =
                    calculate_tx_l1_gas_usage(post_execute_resources, self.block_context)?;
                if actual_used_l1_gas > max_l1_gas {
                    return Err(PostExecutionAuditorError::MaxL1GasAmountExceeded {
                        max_amount: max_l1_gas,
                        actual_amount: actual_used_l1_gas,
                    })?;
                }
            }
            AccountTransactionContext::Deprecated(context) => {
                // Check max fee. If overshot, revert and charge max fee.
                let max_fee = context.max_fee;
                if post_execute_fee > &max_fee {
                    return Err(PostExecutionAuditorError::MaxFeeExceeded {
                        max_fee,
                        actual_fee: *post_execute_fee,
                    })?;
                }
            }
        }

        // Initial check passed; verify against the post-execution account balance, which may have
        // changed post execution.
        let (balance_low, balance_high, can_pay) = get_balance_and_if_covers_fee(
            state,
            self.account_tx_context,
            self.block_context,
            *post_execute_fee,
        )?;
        if can_pay {
            Ok(())
        } else {
            // In pre-validation, balance is verified to cover sender's requested upper bounds,
            // and the current block context is verified to satisfy the sender's price requirements.
            // In post-execution (above), we check the resources charged are within the sender's
            // requested bounds.
            // These checks ensure that the sender *could have paid* the *actual fee*, before
            // execution. So, if the execution state is reverted, the fee transfer is guaranteed
            // to succeed.
            Err(PostExecutionAuditorError::InsufficientFeeTokenBalance {
                fee: *post_execute_fee,
                balance_low,
                balance_high,
            })?
        }
    }

    /// Given a post execution error of a revertible transaction, returns the actual fee and revert
    /// error.
    pub fn post_execution_revert_fee(&self, error: &PostExecutionAuditorError) -> Fee {
        match error {
            // If sender bounds were exceeded, charge based on the sender bounds.
            PostExecutionAuditorError::MaxL1GasAmountExceeded { .. }
            | PostExecutionAuditorError::MaxFeeExceeded { .. } => {
                match self.account_tx_context {
                    AccountTransactionContext::Current(context) => {
                        let max_l1_gas = context
                            .l1_resource_bounds()
                            .expect("L1 gas bounds must be set.")
                            .max_amount as u128;
                        get_fee_by_l1_gas_usage(
                            self.block_context,
                            max_l1_gas,
                            &self.account_tx_context.fee_type(),
                        )
                    }
                    AccountTransactionContext::Deprecated(context) => {
                        // If the transaction is reverted due to exceeding the max fee, the actual
                        // fee is the max fee, and the actual resources are the resources used up
                        // to the max fee.
                        context.max_fee
                    }
                }
            }
            // Balance overdraft error can only occur if sender bound check passes, so once the
            // state change is reverted, the sender's balance can cover the actual fee.
            PostExecutionAuditorError::InsufficientFeeTokenBalance { .. } => {
                self.actual_cost.actual_fee
            }
        }
    }
}
