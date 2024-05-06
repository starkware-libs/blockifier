use std::collections::HashMap;

use cairo_felt::Felt252;
use num_traits::Bounded;
use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::Fee;
use starknet_api::{class_hash, contract_address, patricia_key};

use crate::concurrency::test_utils::safe_versioned_state_for_testing;
use crate::concurrency::worker_logic::_add_fee_to_sequencer_balance;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::state_api::StateReader;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::transaction::objects::FeeType;


#[rstest]
#[case::no_overflow_zero_sequencer_value_high(Fee(50_u128), felt_to_stark_felt(&Felt252::from(100_u128)), StarkFelt::ZERO)]
#[case::no_overflow_non_zero_sequencer_value_high(Fee(50_u128), felt_to_stark_felt(&Felt252::from(100_u128)), StarkFelt::from_u128(3_u128))]
#[case::over_flow_zero_sequencer_value_high(Fee(50_u128), felt_to_stark_felt(&Felt252::max_value()), StarkFelt::ZERO)]
#[case::over_flow_non_zero_sequencer_value_high(Fee(150_u128), felt_to_stark_felt(&Felt252::max_value()), StarkFelt::from_u128(5_u128))]
pub fn test_add_fee_to_sequencer_balance(
    #[case] actual_fee: Fee,
    #[case] sequencer_value_low: StarkFelt,
    #[case] sequencer_value_high: StarkFelt,
) {
    const TEST_CONTRACT_ADDRESS: &str = "0x1";
    const TEST_CLASS_HASH: u8 = 27_u8;
    let init_state = DictStateReader {
        address_to_class_hash: HashMap::from([(
            contract_address!(TEST_CONTRACT_ADDRESS),
            class_hash!(TEST_CLASS_HASH),
        )]),
        ..Default::default()
    };
    let block_context = BlockContext::create_for_account_testing_with_concurrency_mode(true);
    let safe_versioned_state = safe_versioned_state_for_testing(init_state);
    let tx_versioned_state = safe_versioned_state.pin_version(0);
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(&block_context);

    let fee_token_address = block_context.chain_info.fee_token_address(&FeeType::Strk);

    _add_fee_to_sequencer_balance(
        fee_token_address,
        &tx_versioned_state,
        &actual_fee,
        sequencer_balance_key_high,
        sequencer_balance_key_low,
        sequencer_value_high,
        sequencer_value_low,
    );
    let next_tx_versioned_state = safe_versioned_state.pin_version(1);
    if sequencer_value_low > felt_to_stark_felt(&(Felt252::max_value() - Felt252::from(actual_fee.0))) {
        assert_eq!(
            next_tx_versioned_state
                .get_storage_at(fee_token_address, sequencer_balance_key_high)
                .unwrap(),
            felt_to_stark_felt(&(stark_felt_to_felt(sequencer_value_high)+ Felt252::from(1_u8)))
        );
    } else {
        assert_eq!(
            next_tx_versioned_state
                .get_storage_at(fee_token_address, sequencer_balance_key_high)
                .unwrap(),
            felt_to_stark_felt(&(stark_felt_to_felt(sequencer_value_high)))
        );
    }
    assert_eq!(
        next_tx_versioned_state
            .get_storage_at(fee_token_address, sequencer_balance_key_low)
            .unwrap(),
        felt_to_stark_felt(&(stark_felt_to_felt(sequencer_value_low)+ Felt252::from(actual_fee.0)))
    );

}
