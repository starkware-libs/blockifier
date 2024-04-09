use rstest::rstest;
use starknet_api::hash::StarkFelt;

use crate::concurrency::fee_utils::fix_concurrency_fee_transfer_call_info;
use crate::context::BlockContext;
use crate::test_utils::initial_test_state::{fund_account, test_state};
use crate::test_utils::BALANCE;
use crate::transaction::test_utils::{
    block_context, create_fee_transfer_call_data, create_invoke_account_tx,
};

#[rstest]
pub fn test_fix_call_info(
    block_context: BlockContext,
    #[values(50_u128, 100_u128, 150_u128)] sequencer_balance: u128,
) {
    let (account_tx, account) = create_invoke_account_tx();
    let chain_info = &block_context.chain_info;
    let state = &mut test_state(chain_info, BALANCE, &[(account, 1)]);

    let sequencer_address = block_context.block_info.sequencer_address;
    fund_account(chain_info, sequencer_address, sequencer_balance, state);

    let mut concurrency_call_info = create_fee_transfer_call_data(state, &account_tx, true);
    let call_info = create_fee_transfer_call_data(state, &account_tx, false);

    assert_ne!(concurrency_call_info, call_info);

    fix_concurrency_fee_transfer_call_info(
        &mut concurrency_call_info,
        StarkFelt::from(sequencer_balance),
    );

    assert_eq!(concurrency_call_info, call_info);
}
