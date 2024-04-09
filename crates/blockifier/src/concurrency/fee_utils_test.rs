use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::TransactionVersion;

use crate::concurrency::fee_utils::fill_sequencer_balance_reads;
use crate::concurrency::test_utils::create_fee_transfer_call_info;
use crate::context::BlockContext;
use crate::invoke_tx_args;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::{fund_account, test_state};
use crate::test_utils::{
    create_trivial_calldata, CairoVersion, BALANCE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
};
use crate::transaction::test_utils::{account_invoke_tx, block_context, l1_resource_bounds};

#[rstest]
pub fn test_fill_sequencer_balance_reads(block_context: BlockContext) {
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let account_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(0),
        calldata: create_trivial_calldata(account.get_instance_address(0)),
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE
    });
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1)]);

    let sequencer_balance = 100;
    let sequencer_address = block_context.block_info.sequencer_address;
    fund_account(chain_info, sequencer_address, sequencer_balance, &mut state.state);

    let mut concurrency_call_info = create_fee_transfer_call_info(state, &account_tx, true);
    let call_info = create_fee_transfer_call_info(state, &account_tx, false);

    assert_ne!(concurrency_call_info, call_info);

    fill_sequencer_balance_reads(
        &mut concurrency_call_info,
        StarkFelt::from(sequencer_balance),
        StarkFelt::ZERO,
    );

    assert_eq!(concurrency_call_info, call_info);
}
