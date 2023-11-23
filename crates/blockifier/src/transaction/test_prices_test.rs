use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::block_context::BlockContext;
use crate::invoke_tx_args;
use crate::test_utils::{
    create_calldata, InvokeTxArgs, MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
};
use crate::transaction::test_prices::return_result_cost;
use crate::transaction::test_utils::{
    account_invoke_tx, create_state, create_test_init_data, l1_resource_bounds, TestInitData,
};
use crate::transaction::transactions::ExecutableTransaction;

#[rstest]
fn test_return_result_cost(#[values(true, false)] validate: bool) {
    let block_context = BlockContext::create_for_account_testing();
    let max_fee = Fee(MAX_FEE);
    let TestInitData {
        mut state,
        account_address,
        contract_address,
        mut nonce_manager,
        block_context,
    } = create_test_init_data(max_fee, block_context.clone(), create_state(block_context.clone()));

    let tx_execution_info = account_invoke_tx(invoke_tx_args! {
        max_fee,
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        sender_address: account_address,
        calldata: create_calldata(
            contract_address,       // Contract address.
            "return_result",        // EP selector.
            &[stark_felt!(2_u8)]    // Calldata: num.
        ),
        nonce: nonce_manager.next(account_address),
    })
    .execute(&mut state, &block_context, true, validate)
    .unwrap();
    assert_eq!(tx_execution_info.actual_resources, return_result_cost(validate));
}
