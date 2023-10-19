use std::cmp::min;

use starknet_api::transaction::Fee;

use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::execution::entry_point::ExecutionResources;
use crate::state::cached_state::{CachedState, StateChanges, StateChangesCount};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::objects::{
    AccountTransactionContext, HasRelatedFeeType, ResourcesMapping, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::{calculate_l1_gas_usage, calculate_tx_resources};

// TODO(Gilad): Use everywhere instead of passing the `actual_{fee,resources}` tuple, which often
// get passed around together.
pub struct ActualCost {
    pub actual_fee: Fee,
    pub actual_resources: ResourcesMapping,
}

#[derive(Debug, Clone)]
// Invariant: private fields initialized after `new` is called via dedicated methods.
pub struct ActualCostBuilder<'a> {
    pub account_tx_context: AccountTransactionContext,
    pub tx_type: TransactionType,
    pub block_context: BlockContext,
    pub include_nonce_increment_in_fee: bool,
    validate_call_info: Option<&'a CallInfo>,
    execute_call_info: Option<&'a CallInfo>,
    state_changes: StateChanges,
}

impl<'a> ActualCostBuilder<'a> {
    // Recommendation: use constructor from account transaction to build this.
    pub fn new(
        block_context: &BlockContext,
        account_tx_context: AccountTransactionContext,
        tx_type: TransactionType,
        include_nonce_increment_in_fee: bool,
    ) -> Self {
        Self {
            block_context: block_context.clone(),
            account_tx_context,
            tx_type,
            include_nonce_increment_in_fee,
            validate_call_info: None,
            execute_call_info: None,
            state_changes: StateChanges::default(),
        }
    }

    // Call the `build_*` methods to construct the actual cost object, after feeding the builder
    // using the setters below.
    pub fn build_for_non_reverted_tx(
        self,
        execution_resources: &ExecutionResources,
    ) -> TransactionExecutionResult<ActualCost> {
        let is_reverted = false;
        let n_reverted_steps = 0;
        self.calculate_actual_fee_and_resources(execution_resources, is_reverted, n_reverted_steps)
    }

    pub fn build_for_reverted_tx(
        self,
        execution_resources: &ExecutionResources,
        n_reverted_steps: usize,
    ) -> TransactionExecutionResult<ActualCost> {
        let is_reverted = true;
        self.calculate_actual_fee_and_resources(execution_resources, is_reverted, n_reverted_steps)
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

        let sender_address = self.account_tx_context.sender_address();
        let mut new_state_changes = state
            .get_actual_state_changes_for_fee_charge(fee_token_address, Some(sender_address))?;

        // In a validate-only flow, the nonce isn't incremented during the call, so it must
        // be added to the set for manually.
        if self.include_nonce_increment_in_fee {
            new_state_changes.modified_contracts.insert(sender_address);
        }

        self.state_changes = StateChanges::merge(vec![self.state_changes, new_state_changes]);
        Ok(self)
    }

    // Private methods.

    // Construct the actual cost object using all fields that were set in the builder.
    fn calculate_actual_fee_and_resources(
        &self,
        execution_resources: &ExecutionResources,
        is_reverted: bool,
        n_reverted_steps: usize,
    ) -> TransactionExecutionResult<ActualCost> {
        let state_changes_count = StateChangesCount::from(&self.state_changes);
        let non_optional_call_infos = vec![self.validate_call_info, self.execute_call_info]
            .into_iter()
            .flatten()
            .collect::<Vec<&CallInfo>>();
        let l1_gas_usage =
            calculate_l1_gas_usage(&non_optional_call_infos, state_changes_count, None)?;
        let mut actual_resources =
            calculate_tx_resources(execution_resources, l1_gas_usage, self.tx_type)?;

        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            n_reverted_steps;

        let mut actual_fee =
            self.account_tx_context.calculate_tx_fee(&actual_resources, &self.block_context)?;
        if is_reverted || !self.account_tx_context.enforce_fee() {
            // We cannot charge more than max_fee for reverted txs.
            actual_fee = min(actual_fee, self.account_tx_context.max_fee());
        }

        Ok(ActualCost { actual_fee, actual_resources })
    }
}
