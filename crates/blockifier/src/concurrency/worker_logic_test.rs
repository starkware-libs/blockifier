use std::ops::Deref;
use std::sync::Arc;

use cairo_felt::Felt252;
use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::test_utils::versioned_state_for_testing;
use crate::concurrency::versioned_state_proxy::{ThreadSafeVersionedState, VersionedStateProxy};
use crate::concurrency::worker_logic::revalidate_sequencer_balance_reads;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_address_and_keys;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::transaction::test_utils::{block_context, create_invoke_account_tx};

#[rstest]
fn revalidate_sequencer_balance_reads_test(block_context: BlockContext) {
    let contract_address = contract_address!("0x1");
    let storage_key = StorageKey(patricia_key!("0x10"));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let (account_tx, _) = create_invoke_account_tx();
    let versioned_state = versioned_state_for_testing(contract_address, class_hash);
    let mut versioned_state_proxy =
        VersionedStateProxy { state: versioned_state.clone(), tx_index: 0 };
    let safe_versioned_state = ThreadSafeVersionedState(Arc::clone(&versioned_state));
    let transactional_state = CachedState::from(safe_versioned_state.pin_version(1));
    let tx_context = block_context.to_tx_context(&account_tx);
    let (_sequencer_address, sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_address_and_keys(&block_context, false);

    // tx 0 should always pass.
    assert!(revalidate_sequencer_balance_reads(
        &mut versioned_state_proxy,
        &tx_context,
        transactional_state.cache.borrow().deref()
    ));

    versioned_state_proxy.tx_index = 1;
    // Check that changing keys that are not related to the sequencer balance will not affect the
    // result.
    let val = transactional_state.get_storage_at(contract_address, storage_key).unwrap();
    let new_val = felt_to_stark_felt(&(stark_felt_to_felt(val) + Felt252::from(5)));
    transactional_state
        .cache
        .borrow_mut()
        .initial_reads
        .storage
        .insert((contract_address, storage_key), new_val);
    assert!(revalidate_sequencer_balance_reads(
        &mut versioned_state_proxy,
        &tx_context,
        transactional_state.cache.borrow().deref()
    ));
    for storage_key in [sequencer_balance_key_low, sequencer_balance_key_high] {
        // Check that if the sequencer balance in initial read equels to the sequencer balance in
        // the state the function will return true.
        let seq_balance = transactional_state
            .get_storage_at(tx_context.fee_token_address(), storage_key)
            .unwrap();
        assert!(revalidate_sequencer_balance_reads(
            &mut versioned_state_proxy,
            &tx_context,
            transactional_state.cache.borrow().deref()
        ));

        // Check that if the sequencer balance in initial read is different from the sequencer
        // balance in the state the function will return false.
        let new_seq_balance =
            felt_to_stark_felt(&(stark_felt_to_felt(seq_balance) + Felt252::from(5)));
        transactional_state
            .cache
            .borrow_mut()
            .initial_reads
            .storage
            .insert((tx_context.fee_token_address(), storage_key), new_seq_balance);
        assert!(!revalidate_sequencer_balance_reads(
            &mut versioned_state_proxy,
            &tx_context,
            transactional_state.cache.borrow().deref()
        ));

        // Reset the changes in the sequencer balance.
        transactional_state
            .cache
            .borrow_mut()
            .initial_reads
            .storage
            .insert((tx_context.fee_token_address(), storage_key), seq_balance);
    }
}
