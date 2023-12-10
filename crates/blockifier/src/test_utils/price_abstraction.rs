use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::core::ContractAddress;
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::transaction::{Calldata, TransactionVersion};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::{
    CallEntryPoint, CallType, EntryPointExecutionContext, ExecutionResources,
};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::invoke_tx_args;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE};
use crate::transaction::constants;
use crate::transaction::test_utils::account_invoke_tx;

#[cfg(test)]
#[path = "price_abstraction_test.rs"]
pub mod test;

pub fn validate_resources(
    block_context: &BlockContext,
    cairo_version: CairoVersion,
    tx_version: TransactionVersion,
    validate_calldata: Calldata,
) -> VmExecutionResources {
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let state = &mut test_state(block_context, BALANCE, &[(account, 1)]);
    let account_tx = account_invoke_tx(invoke_tx_args! { version: tx_version });
    let validate_call = CallEntryPoint {
        entry_point_type: EntryPointType::External,
        entry_point_selector: selector_from_name(constants::VALIDATE_ENTRY_POINT_NAME),
        calldata: validate_calldata,
        class_hash: None,
        code_address: None,
        storage_address: account.get_instance_address(0),
        caller_address: ContractAddress::default(),
        call_type: CallType::Call,
        initial_gas: u64::MAX,
    };

    execute_entry_point_call(
        validate_call,
        account.get_class(),
        state,
        &mut ExecutionResources::default(),
        &mut EntryPointExecutionContext::new(
            block_context,
            &account_tx.get_account_tx_context(),
            ExecutionMode::Validate,
            false,
        )
        .unwrap(),
    )
    .unwrap()
    .vm_resources
}
