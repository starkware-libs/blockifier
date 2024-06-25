use cairo_felt::Felt252;
use num_bigint::BigUint;
use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::concurrency::fee_utils::{add_fee_to_sequencer_balance, fill_sequencer_balance_reads};
use crate::concurrency::test_utils::create_fee_transfer_call_info;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::invoke_tx_args;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::{fund_account, test_state, test_state_inner};
use crate::test_utils::{
    create_trivial_calldata, CairoVersion, BALANCE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE,
};
use crate::transaction::objects::FeeType;
use crate::transaction::test_utils::{account_invoke_tx, block_context, l1_resource_bounds};

#[rstest]
pub fn test_fill_sequencer_balance_reads(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] erc20_version: CairoVersion,
) {
    let account = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let account_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account.get_instance_address(0),
        calldata: create_trivial_calldata(account.get_instance_address(0)),
        resource_bounds: l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE),
        version: TransactionVersion::THREE
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
        (StarkFelt::from(sequencer_balance), StarkFelt::ZERO),
    );

    assert_eq!(concurrency_call_info, call_info);
}

#[rstest]
#[case::no_overflow(Fee(50_u128), stark_felt!(100_u128), StarkFelt::ZERO)]
#[case::overflow(Fee(150_u128), stark_felt!(u128::MAX), stark_felt!(5_u128))]
#[case::overflow_edge_case(Fee(500_u128), stark_felt!(u128::MAX), stark_felt!(u128::MAX-1))]
pub fn test_add_fee_to_sequencer_balance(
    #[case] actual_fee: Fee,
    #[case] sequencer_balance_low: StarkFelt,
    #[case] sequencer_balance_high: StarkFelt,
) {
    let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(true);
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
    let expected_balance =
        (stark_felt_to_felt(sequencer_balance_low) + Felt252::from(actual_fee.0)).to_biguint();

    let mask_128_bit = (BigUint::from(1_u8) << 128) - 1_u8;
    let expected_sequencer_balance_value_low = Felt252::from(&expected_balance & mask_128_bit);
    let expected_sequencer_balance_value_high =
        stark_felt_to_felt(sequencer_balance_high) + Felt252::from(&expected_balance >> 128);

    assert_eq!(
        new_sequencer_balance_value_low,
        felt_to_stark_felt(&expected_sequencer_balance_value_low)
    );
    assert_eq!(
        new_sequencer_balance_value_high,
        felt_to_stark_felt(&expected_sequencer_balance_value_high)
    );
}
