use num_bigint::BigUint;
use rstest::rstest;
use starknet_api::felt;
use starknet_api::transaction::{Fee, ResourceBoundsMapping};
use starknet_types_core::felt::Felt;

use crate::concurrency::fee_utils::{add_fee_to_sequencer_balance, fill_sequencer_balance_reads};
use crate::concurrency::test_utils::create_fee_transfer_call_info;
use crate::context::BlockContext;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::invoke_tx_args;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::{fund_account, test_state, test_state_inner};
use crate::test_utils::{create_trivial_calldata, CairoVersion, BALANCE};
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::{account_invoke_tx, block_context, max_resource_bounds};

#[rstest]
pub fn test_fill_sequencer_balance_reads(
    block_context: BlockContext,
    max_resource_bounds: ResourceBoundsMapping,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] erc20_version: CairoVersion,
) {
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let account_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(0),
        calldata: create_trivial_calldata(account.get_instance_address(0)),
        resource_bounds: max_resource_bounds,
    });
    let chain_info = &block_context.chain_info;
    let state = &mut test_state_inner(chain_info, BALANCE, &[(account, 1)], erc20_version);

    let sequencer_balance = 100;
    let sequencer_address = block_context.block_info.sequencer_address;
    fund_account(chain_info, sequencer_address, sequencer_balance, &mut state.state);

    let mut concurrency_call_info = create_fee_transfer_call_info(state, &account_tx, true);
    let call_info = create_fee_transfer_call_info(state, &account_tx, false);

    assert_ne!(concurrency_call_info, call_info);

    fill_sequencer_balance_reads(
        &mut concurrency_call_info,
        (Felt::from(sequencer_balance), Felt::ZERO),
    );

    assert_eq!(concurrency_call_info, call_info);
}

#[rstest]
#[case::no_overflow(Fee(50_u128), felt!(100_u128), Felt::ZERO)]
#[case::overflow(Fee(150_u128), felt!(u128::MAX), felt!(5_u128))]
#[case::overflow_edge_case(Fee(500_u128), felt!(u128::MAX), felt!(u128::MAX-1))]
pub fn test_add_fee_to_sequencer_balance(
    #[case] actual_fee: starknet_api::transaction::Fee,
    #[case] sequencer_balance_low: Felt,
    #[case] sequencer_balance_high: Felt,
) {
    let block_context = BlockContext::create_for_account_testing();
    let account = FeatureContract::Empty(CairoVersion::Cairo1);
    let mut state = test_state(&block_context.chain_info, 0, &[(account, 1)]);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&block_context);

    let fee_token_address = block_context.chain_info.fee_token_address(&FeeType::Strk);

    add_fee_to_sequencer_balance(
        fee_token_address,
        &mut state,
        actual_fee,
        &block_context,
        (sequencer_balance_low, sequencer_balance_high),
    );

    let new_sequencer_balance_value_low =
        state.get_storage_at(fee_token_address, sequencer_balance_key_low).unwrap();
    let new_sequencer_balance_value_high =
        state.get_storage_at(fee_token_address, sequencer_balance_key_high).unwrap();
    let expected_balance = (sequencer_balance_low + Felt::from(actual_fee.0)).to_biguint();

    let mask_128_bit = (BigUint::from(1_u8) << 128) - 1_u8;
    let expected_sequencer_balance_value_low = Felt::from(&expected_balance & mask_128_bit);
    let expected_sequencer_balance_value_high =
        sequencer_balance_high + Felt::from(&expected_balance >> 128);

    assert_eq!(new_sequencer_balance_value_low, expected_sequencer_balance_value_low);
    assert_eq!(new_sequencer_balance_value_high, expected_sequencer_balance_value_high);
}
