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
struct ActualCostParameters<'a, T: Iterator<Item = &'a CallInfo> + Clone> {
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
pub struct ActualCost {
    pub actual_fee: Fee,
    pub da_gas: GasVector,
    pub actual_resources: TransactionResources,
    pub actual_gas_cost: GasVector,
}

impl ActualCost {
    fn from_params<'a, T: Iterator<Item = &'a CallInfo> + Clone>(
        actual_cost_params: ActualCostParameters<'a, T>,
    ) -> TransactionExecutionResult<Self> {
        let ActualCostParameters {
            tx_context,
            calldata_length,
            signature_length,
            code_size,
            state_changes,
            sender_address,
            l1_handler_payload_size,
            call_infos,
            execution_resources,
            tx_type,
            reverted_steps,
        } = actual_cost_params;

        let starknet_resources = StarknetResources::new(
            calldata_length,
            signature_length,
            code_size,
            state_changes.count_for_fee_charge(sender_address, tx_context.fee_token_address()),
            l1_handler_payload_size,
            call_infos,
        );

        let mut vm_resources = (execution_resources
            + &tx_context.block_context.versioned_constants.get_additional_os_tx_resources(
                tx_type,
                &starknet_resources,
                tx_context.block_context.block_info.use_kzg_da,
            )?)
            .filter_unused_builtins();
        // TODO(Dori, 1/5/2024): Once TransactionResources keeps reverted steps separately, do not
        //   add them to the VM resources.
        vm_resources.n_steps += reverted_steps;

        let tx_resources = TransactionResources { starknet_resources, vm_resources };

        // L1 handler transactions are not charged an L2 fee but it is compared to the L1 fee.
        let actual_fee =
            if tx_context.tx_info.enforce_fee()? || tx_type == TransactionType::L1Handler {
                tx_context.tx_info.calculate_tx_fee(&tx_resources, &tx_context.block_context)?
            } else {
                Fee(0)
            };
        let da_gas = tx_resources
            .starknet_resources
            .get_state_changes_cost(tx_context.block_context.block_info.use_kzg_da);

        let actual_gas_cost = tx_resources.to_gas_vector(
            &tx_context.block_context.versioned_constants,
            tx_context.block_context.block_info.use_kzg_da,
        )?;
        Ok(Self { actual_resources: tx_resources, actual_gas_cost, da_gas, actual_fee })
    }

    /// Computes actual cost of an L1 handler transaction.
    pub fn of_l1_handler<'a>(
        tx_context: &'a TransactionContext,
        l1_handler_payload_size: usize,
        call_infos: impl Iterator<Item = &'a CallInfo> + Clone,
        state_changes: &'a StateChanges,
        execution_resources: &'a ExecutionResources,
    ) -> TransactionExecutionResult<Self> {
        Self::from_params(ActualCostParameters {
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
    pub fn of_account_tx<'a>(
        account_tx: &'a AccountTransaction,
        tx_context: &'a TransactionContext,
        state_changes: &'a StateChanges,
        execution_resources: &'a ExecutionResources,
        call_infos: impl Iterator<Item = &'a CallInfo> + Clone,
        reverted_steps: usize,
    ) -> TransactionExecutionResult<Self> {
        Self::from_params(ActualCostParameters {
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
