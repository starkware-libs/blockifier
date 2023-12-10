use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::core::ContractAddress;
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::selector_from_name;
use crate::block_context::BlockContext;
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::{
    CallEntryPoint, CallType, EntryPointExecutionContext, ExecutionResources,
};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::invoke::InvokeTxArgs;
use crate::test_utils::{CairoVersion, BALANCE};
use crate::transaction::constants;
use crate::transaction::test_utils::account_invoke_tx;

#[cfg(test)]
#[path = "price_abstraction_test.rs"]
pub mod test;

pub fn validate_resources(cairo_version: CairoVersion) -> VmExecutionResources {
    let block_context = &BlockContext::create_for_account_testing();
    let account = FeatureContract::AccountWithoutValidations(cairo_version);
    let state = &mut test_state(block_context, BALANCE, &[(account, 1)]);
    let account_tx = account_invoke_tx(InvokeTxArgs::default());
    let validate_call = CallEntryPoint {
        entry_point_type: EntryPointType::External,
        entry_point_selector: selector_from_name(constants::VALIDATE_ENTRY_POINT_NAME),
        calldata: calldata![stark_felt!("0xdead"), stark_felt!("0xbeef"), stark_felt!(0_u8)],
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
