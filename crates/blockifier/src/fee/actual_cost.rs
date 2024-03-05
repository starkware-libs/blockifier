use std::sync::Arc;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::ContractAddress;
use starknet_api::transaction::Fee;

use crate::abi::constants as abi_constants;
use crate::context::TransactionContext;
use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::ClassInfo;
use crate::fee::gas_usage::{get_messages_gas_cost, get_tx_events_gas_cost};
use crate::state::cached_state::{CachedState, StateChanges, StateChangesCount};
use crate::state::state_api::{StateReader, StateResult};
use crate::transaction::objects::{
    GasVector, HasRelatedFeeType, ResourcesMapping, StarknetResources, TransactionExecutionResult,
};
use crate::transaction::transaction_types::TransactionType;
use crate::transaction::transaction_utils::calculate_tx_resources;
use crate::versioned_constants::VersionedConstants;

#[cfg(test)]
#[path = "actual_cost_test.rs"]
pub mod test;

// TODO(Gilad): Use everywhere instead of passing the `actual_{fee,resources}` tuple, which often
// get passed around together.
#[derive(Default)]
pub struct ActualCost {
    pub actual_fee: Fee,
    pub da_gas: GasVector,
    pub actual_resources: ResourcesMapping,
}

impl ActualCost {
    pub fn builder_for_l1_handler<'a>(
        tx_context: Arc<TransactionContext>,
        l1_handler_payload_size: usize,
    ) -> ActualCostBuilder<'a> {
        let signature_length = 0; // Signature is validated on L1.
        ActualCostBuilder::new(
            tx_context,
            TransactionType::L1Handler,
            l1_handler_payload_size,
            signature_length,
        )
        .without_sender_address()
        .with_l1_payload_size(l1_handler_payload_size)
    }
}

#[derive(Debug, Clone)]
// Invariant: private fields initialized after `new` is called via dedicated methods.
pub struct ActualCostBuilder<'a> {
    pub tx_context: Arc<TransactionContext>,
    pub tx_type: TransactionType,
    starknet_resources: StarknetResources,
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
        tx_context: Arc<TransactionContext>,
        tx_type: TransactionType,
        calldata_length: usize,
        signature_length: usize,
    ) -> Self {
        Self {
            starknet_resources: StarknetResources::new(
                calldata_length,
                signature_length,
                None,
                StateChangesCount::default(),
            ),
            sender_address: Some(tx_context.tx_info.sender_address()),
            tx_context,
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

    /// Calls the `build` method to construct the actual cost object, after feeding the builder
    /// using the setters below.
    /// In addition to actual cost, the method returns the resources the bouncer should take into
    /// account when adding the transaction to the block.
    pub fn build(
        self,
        execution_resources: &ExecutionResources,
    ) -> TransactionExecutionResult<(ActualCost, ResourcesMapping)> {
        self.calculate_actual_fee_and_resources(execution_resources)
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

    pub fn with_class_info(mut self, class_info: ClassInfo) -> Self {
        self.starknet_resources.set_code_size(Some(&class_info));
        self
    }

    pub fn try_add_state_changes(
        mut self,
        state: &mut CachedState<impl StateReader>,
    ) -> StateResult<Self> {
        let new_state_changes = state.get_actual_state_changes()?;
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

    fn use_kzg_da(&self) -> bool {
        self.tx_context.block_context.block_info.use_kzg_da
    }

    // Construct the actual cost object using all fields that were set in the builder.
    fn calculate_actual_fee_and_resources(
        mut self,
        execution_resources: &ExecutionResources,
    ) -> TransactionExecutionResult<(ActualCost, ResourcesMapping)> {
        let use_kzg_da = self.use_kzg_da();
        self.starknet_resources.state_changes_count = self.state_changes.count_for_fee_charge(
            self.sender_address,
            self.tx_context
                .block_context
                .chain_info
                .fee_token_address(&self.tx_context.tx_info.fee_type()),
        );
        // TODO(Dafna, 1/6/2024): Compute the DA size and pass it instead of state_changes_count.
        let da_gas = self.starknet_resources.get_state_changes_cost(use_kzg_da);
        let non_optional_call_infos = &[&self.validate_call_info, &self.execute_call_info];
        // Gas usage for SHARP costs and Starknet L1-L2 messages. Includes gas usage for data
        // availability.
        let gas_usage_vector = Self::calculate_tx_gas_usage_vector(
            &self.tx_context.block_context.versioned_constants,
            non_optional_call_infos,
            &self.starknet_resources,
            self.l1_payload_size,
            use_kzg_da,
        )?;

        let mut actual_resources = calculate_tx_resources(
            &self.tx_context.block_context.versioned_constants,
            execution_resources,
            gas_usage_vector,
            self.tx_type,
            &self.starknet_resources,
            use_kzg_da,
        )?;

        // Bouncer resources should not include reverted steps; should include the rest, though.
        let bouncer_resources = actual_resources.clone();

        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            self.n_reverted_steps;

        let tx_info = &self.tx_context.tx_info;
        let actual_fee = if tx_info.enforce_fee()?
        // L1 handler transactions are not charged an L2 fee but it is compared to the L1 fee.
            || self.tx_type == TransactionType::L1Handler
        {
            tx_info.calculate_tx_fee(&actual_resources, &self.tx_context.block_context)?
        } else {
            Fee(0)
        };

        Ok((ActualCost { actual_fee, da_gas, actual_resources }, bouncer_resources))
    }

    /// Returns the gas usage of a transaction, specifically:
    /// * L1 gas, used by Starknet's state update and the Verifier, e.g., a message from L2 to L1 is
    ///   followed by a storage write operation on L1.
    /// * L1 data gas, for publishing data availability.
    /// * L2 resources cost, e.g., for storing transaction calldata.
    fn calculate_tx_gas_usage_vector(
        versioned_constants: &VersionedConstants,
        call_infos: &[&Option<&CallInfo>],
        starknet_resources: &StarknetResources,
        l1_handler_payload_size: Option<usize>,
        use_kzg_da: bool,
    ) -> TransactionExecutionResult<GasVector> {
        Ok(get_messages_gas_cost(call_infos, l1_handler_payload_size)?
            + starknet_resources.to_gas_vector(versioned_constants, use_kzg_da)
            + get_tx_events_gas_cost(call_infos, versioned_constants))
    }
}
