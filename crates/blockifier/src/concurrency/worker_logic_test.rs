use cairo_felt::Felt252;
use num_traits::Bounded;
use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Fee;

use crate::concurrency::test_utils::safe_versioned_state_for_testing;
use crate::concurrency::worker_logic::_add_fee_to_sequencer_balance;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state_reader;
use crate::test_utils::CairoVersion;
use crate::transaction::objects::FeeType;

#[rstest]
#[case::no_overflow(Fee(50_u128), felt_to_stark_felt(&Felt252::from(100_u128)), StarkFelt::ZERO)]
#[case::overflow(Fee(150_u128), felt_to_stark_felt(&Felt252::max_value()), StarkFelt::from_u128(5_u128))]
pub fn test_add_fee_to_sequencer_balance(
    #[case] actual_fee: Fee,
    #[case] sequencer_value_low: StarkFelt,
    #[case] sequencer_value_high: StarkFelt,
) {
    let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(true);
    let account = FeatureContract::Empty(CairoVersion::Cairo1);
    let safe_versioned_state = safe_versioned_state_for_testing(test_state_reader(
        &block_context.chain_info,
        0,
        &[(account, 1)],
    ));
    let tx_versioned_state = safe_versioned_state.pin_version(0);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&block_context);

    let fee_token_address = block_context.chain_info.fee_token_address(&FeeType::Strk);

    _add_fee_to_sequencer_balance(
        fee_token_address,
        &tx_versioned_state,
        actual_fee,
        &block_context,
        sequencer_value_high,
        sequencer_value_low,
    );
    let next_tx_versioned_state = safe_versioned_state.pin_version(1);

    let new_sequencer_balance_value_low = next_tx_versioned_state
        .get_storage_at(fee_token_address, sequencer_balance_key_low)
        .unwrap();
    let new_sequencer_balance_value_high = next_tx_versioned_state
        .get_storage_at(fee_token_address, sequencer_balance_key_high)
        .unwrap();

    let expected_sequencer_balance_value_low =
        stark_felt_to_felt(sequencer_value_low) + Felt252::from(actual_fee.0);
    let overflow = sequencer_value_low
        > felt_to_stark_felt(&(Felt252::max_value() - Felt252::from(actual_fee.0)));
    let expected_value_high = if overflow {
        stark_felt_to_felt(sequencer_value_high) + Felt252::from(1_u128)
    } else {
        stark_felt_to_felt(sequencer_value_high)
    };

    assert_eq!(
        new_sequencer_balance_value_low,
        felt_to_stark_felt(&expected_sequencer_balance_value_low)
    );
    assert_eq!(new_sequencer_balance_value_high, felt_to_stark_felt(&expected_value_high));
}
