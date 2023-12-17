use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};

use crate::abi::abi_utils::{get_fee_token_var_address, selector_from_name};
use crate::block_context::BlockContext;
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::{
    CallEntryPoint, EntryPointExecutionContext, ExecutionResources,
};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::state::state_api::State;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::invoke::InvokeTxArgs;
use crate::test_utils::BALANCE;
use crate::transaction::constants;
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::account_invoke_tx;

/// Returns the expected VM resource consumption for a fee transfer call from the given address.
#[memoize::memoize]
pub fn fee_transfer_resources(account_contract_address: ContractAddress) -> VmExecutionResources {
    let token = FeatureContract::ERC20;
    let block_context = &BlockContext::create_for_account_testing();
    let state = &mut test_state(block_context, BALANCE, &[]);

    // Fund the account so we don't hit an error.
    state.set_storage_at(
        block_context.fee_token_address(&FeeType::Eth),
        get_fee_token_var_address(&account_contract_address),
        stark_felt!(BALANCE),
    );

    // Execute a fee transfer call and return the VM resources used.
    let fee_transfer_call = CallEntryPoint {
        class_hash: Some(token.get_class_hash()),
        entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
        calldata: calldata![
            *block_context.sequencer_address.0.key(), // Recipient.
            stark_felt!(7_u8),                        // Amount.
            stark_felt!(0_u8)
        ],
        storage_address: block_context.fee_token_address(&FeeType::Eth),
        caller_address: account_contract_address,
        ..Default::default()
    };
    execute_entry_point_call(
        fee_transfer_call,
        token.get_class(),
        state,
        &mut ExecutionResources::default(),
        &mut EntryPointExecutionContext::new(
            block_context,
            &account_invoke_tx(InvokeTxArgs::default()).get_account_tx_context(),
            ExecutionMode::Validate,
            false,
        )
        .unwrap(),
    )
    .unwrap()
    .vm_resources
}
