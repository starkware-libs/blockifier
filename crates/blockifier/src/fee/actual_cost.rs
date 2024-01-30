use starknet_api::core::ContractAddress;
use starknet_api::transaction::Fee;

use crate::abi::constants as abi_constants;
use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::execution::entry_point::ExecutionResources;
use crate::fee::gas_usage::calculate_tx_gas_and_blob_gas_usage;
use crate::state::cached_state::{CachedState, StateChanges, StateChangesCount};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::objects::{
    AccountTransactionContext, FeeType, HasRelatedFeeType, ResourcesMapping,
    TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::calculate_tx_resources;

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
        ActualCostBuilder::new(
            block_context,
            tx_context,
            TransactionType::L1Handler,
            l1_handler_payload_size,
        )
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
    calldata_length: usize,
    n_reverted_steps: usize,
}

pub fn get_block_context_dependent_state_changes(
    fee_type: &FeeType,
    block_context: &BlockContext,
    sender_address: Option<ContractAddress>,
    state: &mut CachedState<impl StateReader>,
) -> StateResult<StateChanges> {
    let fee_token_address = block_context.chain_info.fee_token_address(fee_type);
    state.get_actual_state_changes_for_fee_charge(fee_token_address, sender_address)
}

impl<'a> ActualCostBuilder<'a> {
    // Recommendation: use constructor from account transaction, or from actual cost, to build this.
    pub fn new(
        block_context: &BlockContext,
        account_tx_context: AccountTransactionContext,
        tx_type: TransactionType,
        calldata_length: usize,
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
            calldata_length,
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
        let new_state_changes = get_block_context_dependent_state_changes(
            &self.account_tx_context.fee_type(),
            &self.block_context,
            self.sender_address,
            state,
        )?;
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
        let non_optional_call_infos =
            self.validate_call_info.into_iter().chain(self.execute_call_info);
        // Gas usage for SHARP costs and Starknet L1-L2 messages. Includes gas usage for data
        // availability.
        // TODO(Aner, 21/01/24) Include gas for data availability according to use_kzg_da flag.
        let l1_gas_and_blob_gas_usage = calculate_tx_gas_and_blob_gas_usage(
            non_optional_call_infos,
            state_changes_count,
            self.l1_payload_size,
        )?;

        let mut actual_resources = calculate_tx_resources(
            execution_resources,
            l1_gas_and_blob_gas_usage,
            self.tx_type,
            self.calldata_length,
        )?;

        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            n_reverted_steps;

        let actual_fee = if self.account_tx_context.enforce_fee()?
        // L1 handler transactions are not charged an L2 fee but it is compared to the L1 fee.
            || self.tx_type == TransactionType::L1Handler
        {
            self.account_tx_context.calculate_tx_fee(&actual_resources, &self.block_context)?
        } else {
            Fee(0)
        };

        Ok(ActualCost { actual_fee, actual_resources })
    }
}
