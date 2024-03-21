use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::ContractAddress;
use starknet_api::transaction::Fee;

use crate::context::TransactionContext;
use crate::execution::call_info::CallInfo;
use crate::state::cached_state::StateChanges;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::objects::{
    GasVector, HasRelatedFeeType, StarknetResources, TransactionExecutionResult,
    TransactionResources,
};
use crate::transaction::transaction_types::TransactionType;

#[cfg(test)]
#[path = "actual_cost_test.rs"]
pub mod test;

/// Parameters required to compute actual cost of a transaction.
struct TransactionReceiptParameters<'a, T: Iterator<Item = &'a CallInfo> + Clone> {
    tx_context: &'a TransactionContext,
    calldata_length: usize,
    signature_length: usize,
    code_size: usize,
    state_changes: &'a StateChanges,
    sender_address: Option<ContractAddress>,
    l1_handler_payload_size: Option<usize>,
    call_infos: T,
    execution_resources: &'a ExecutionResources,
    tx_type: TransactionType,
    reverted_steps: usize,
}

// TODO(Gilad): Use everywhere instead of passing the `actual_{fee,resources}` tuple, which often
// get passed around together.
#[derive(Default)]
pub struct TransactionReceipt {
    pub fee: Fee,
    pub gas: GasVector,
    pub da_gas: GasVector,
    pub resources: TransactionResources,
}

impl TransactionReceipt {
    fn from_params<'a, T: Iterator<Item = &'a CallInfo> + Clone>(
        tx_receipt_params: TransactionReceiptParameters<'a, T>,
    ) -> TransactionExecutionResult<Self> {
        let TransactionReceiptParameters {
            tx_context,
            calldata_length,
            signature_length,
<<<<<<< HEAD
            code_size,
            state_changes,
            sender_address,
            l1_handler_payload_size,
            call_infos,
||||||| a8460971
            class_info: None,
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
        self.class_info = Some(class_info);
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
        self,
        execution_resources: &ExecutionResources,
    ) -> TransactionExecutionResult<ActualCost> {
        let use_kzg_da = self.use_kzg_da();
        let state_changes_count = self.state_changes.count_for_fee_charge(
            self.sender_address,
            self.tx_context
                .block_context
                .chain_info
                .fee_token_address(&self.tx_context.tx_info.fee_type()),
        );
        let da_gas = get_da_gas_cost(state_changes_count, use_kzg_da);
        let non_optional_call_infos =
            self.validate_call_info.into_iter().chain(self.execute_call_info);
        // Gas usage for SHARP costs and Starknet L1-L2 messages. Includes gas usage for data
        // availability.
        let gas_usage_vector = Self::calculate_tx_gas_usage_vector(
            &self.tx_context.block_context.versioned_constants,
            non_optional_call_infos,
            state_changes_count,
            self.calldata_length,
            self.signature_length,
            self.l1_payload_size,
            self.class_info,
            use_kzg_da,
        )?;

        let mut actual_resources = calculate_tx_resources(
            &self.tx_context.block_context.versioned_constants,
=======
            class_info: None,
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
        self.class_info = Some(class_info);
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
        self,
        execution_resources: &ExecutionResources,
    ) -> TransactionExecutionResult<(ActualCost, ResourcesMapping)> {
        let use_kzg_da = self.use_kzg_da();
        let state_changes_count = self.state_changes.count_for_fee_charge(
            self.sender_address,
            self.tx_context
                .block_context
                .chain_info
                .fee_token_address(&self.tx_context.tx_info.fee_type()),
        );
        let da_gas = get_da_gas_cost(state_changes_count, use_kzg_da);
        let non_optional_call_infos =
            self.validate_call_info.into_iter().chain(self.execute_call_info);
        // Gas usage for SHARP costs and Starknet L1-L2 messages. Includes gas usage for data
        // availability.
        let gas_usage_vector = Self::calculate_tx_gas_usage_vector(
            &self.tx_context.block_context.versioned_constants,
            non_optional_call_infos,
            state_changes_count,
            self.calldata_length,
            self.signature_length,
            self.l1_payload_size,
            self.class_info,
            use_kzg_da,
        )?;

        let mut actual_resources = calculate_tx_resources(
            &self.tx_context.block_context.versioned_constants,
>>>>>>> origin/main-v0.13.1
            execution_resources,
            tx_type,
            reverted_steps,
        } = tx_receipt_params;

<<<<<<< HEAD
        let starknet_resources = StarknetResources::new(
            calldata_length,
            signature_length,
            code_size,
            state_changes.count_for_fee_charge(sender_address, tx_context.fee_token_address()),
            l1_handler_payload_size,
            call_infos,
        );

        let mut cairo_resources = (execution_resources
            + &tx_context.block_context.versioned_constants.get_additional_os_tx_resources(
                tx_type,
                &starknet_resources,
                tx_context.block_context.block_info.use_kzg_da,
            )?)
            .filter_unused_builtins();
        // TODO(Dori, 1/5/2024): Once TransactionResources keeps reverted steps separately, do not
        //   add them to the VM resources.
        cairo_resources.n_steps += reverted_steps;

        let tx_resources =
            TransactionResources { starknet_resources, vm_resources: cairo_resources };
||||||| a8460971
        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            self.n_reverted_steps;
=======
        // Bouncer resources should not include reverted steps; should include the rest, though.
        let bouncer_resources = actual_resources.clone();

        // Add reverted steps to actual_resources' n_steps for correct fee charge.
        *actual_resources.0.get_mut(&abi_constants::N_STEPS_RESOURCE.to_string()).unwrap() +=
            self.n_reverted_steps;
>>>>>>> origin/main-v0.13.1

        // L1 handler transactions are not charged an L2 fee but it is compared to the L1 fee.
        let fee = if tx_context.tx_info.enforce_fee()? || tx_type == TransactionType::L1Handler {
            tx_context.tx_info.calculate_tx_fee(&tx_resources, &tx_context.block_context)?
        } else {
            Fee(0)
        };
        let da_gas = tx_resources
            .starknet_resources
            .get_state_changes_cost(tx_context.block_context.block_info.use_kzg_da);

<<<<<<< HEAD
        let gas = tx_resources.to_gas_vector(
            &tx_context.block_context.versioned_constants,
            tx_context.block_context.block_info.use_kzg_da,
        )?;
        Ok(Self { resources: tx_resources, gas, da_gas, fee })
||||||| a8460971
        Ok(ActualCost { actual_fee, da_gas, actual_resources })
=======
        Ok((ActualCost { actual_fee, da_gas, actual_resources }, bouncer_resources))
>>>>>>> origin/main-v0.13.1
    }

    /// Computes actual cost of an L1 handler transaction.
    pub fn from_l1_handler<'a>(
        tx_context: &'a TransactionContext,
        l1_handler_payload_size: usize,
        call_infos: impl Iterator<Item = &'a CallInfo> + Clone,
        state_changes: &'a StateChanges,
        execution_resources: &'a ExecutionResources,
    ) -> TransactionExecutionResult<Self> {
        Self::from_params(TransactionReceiptParameters {
            tx_context,
            calldata_length: l1_handler_payload_size,
            signature_length: 0, // Signature is validated on L1.
            code_size: 0,
            state_changes,
            sender_address: None, // L1 handlers have no sender address.
            l1_handler_payload_size: Some(l1_handler_payload_size),
            call_infos,
            execution_resources,
            tx_type: TransactionType::L1Handler,
            reverted_steps: 0,
        })
    }

    /// Computes actual cost of an account transaction.
    pub fn from_account_tx<'a>(
        account_tx: &'a AccountTransaction,
        tx_context: &'a TransactionContext,
        state_changes: &'a StateChanges,
        execution_resources: &'a ExecutionResources,
        call_infos: impl Iterator<Item = &'a CallInfo> + Clone,
        reverted_steps: usize,
    ) -> TransactionExecutionResult<Self> {
        Self::from_params(TransactionReceiptParameters {
            tx_context,
            calldata_length: account_tx.calldata_length(),
            signature_length: account_tx.signature_length(),
            code_size: account_tx.declare_code_size(),
            state_changes,
            sender_address: Some(tx_context.tx_info.sender_address()),
            l1_handler_payload_size: None,
            call_infos,
            execution_resources,
            tx_type: account_tx.tx_type(),
            reverted_steps,
        })
    }
}
