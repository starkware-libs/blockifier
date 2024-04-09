use std::sync::Arc;

use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::concurrency::fee_utils::fix_call_info;
use crate::context::BlockContext;
use crate::declare_tx_args;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::declare::declare_tx;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, BALANCE, MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::test_utils::{
    block_context, calculate_class_info_for_testing, expected_fee_transfer_call_info,
    l1_resource_bounds,
};

#[rstest]
pub fn test_fix_call_info(block_context: BlockContext) {
    let empty_contract = FeatureContract::Empty(CairoVersion::Cairo1);
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1)]);
    let class_hash = empty_contract.get_class_hash();
    let class_info = calculate_class_info_for_testing(empty_contract.get_class());
    let sender_address = account.get_instance_address(0);

    let account_tx = declare_tx(
        declare_tx_args! {
            max_fee: Fee(MAX_FEE),
            sender_address,
            version: TransactionVersion::THREE,
            resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
            class_hash,
        },
        class_info.clone(),
    );

    let tx_context = Arc::new(block_context.to_tx_context(&account_tx));

    // Case 1: The transaction did not read form/ write to the sequenser balance before executing
    // fee transfer.
    let mut transactional_state = CachedState::create_transactional(state);
    let mut call_info = AccountTransaction::concurrency_execute_fee_transfer(
        &mut transactional_state,
        tx_context,
        Fee(100_u128),
    )
    .unwrap();
    let tx_context = Arc::new(block_context.to_tx_context(&account_tx));
    let expected_call_info = expected_fee_transfer_call_info(
        &tx_context,
        sender_address,
        Fee(100_u128),
        FeatureContract::ERC20.get_class_hash(),
    )
    .unwrap();
    fix_call_info(&mut call_info, StarkFelt::from(0_u8));
    assert_eq!(call_info, expected_call_info);
}
