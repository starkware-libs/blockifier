use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{contract_address, patricia_key, stark_felt};

use crate::concurrency::validator::{validate_read_set, StorageEntry, StorageType};
use crate::concurrency::versioned_state::VersionedState;
use crate::test_utils::dict_state_reader::DictStateReader;

#[test]
fn test_versioned_state() {
    let mut versioned_state = VersionedState::new(DictStateReader::default());

    // Test data
    let contract_address = contract_address!("0x1");
    let key = StorageKey(patricia_key!("0x10"));
    let nonce = Nonce(stark_felt!(20_u8));
    let class_hash = ClassHash(stark_felt!(27_u8));
    let compiled_class_hash = CompiledClassHash(stark_felt!(29_u8));

    // Write initial data to the state.
    versioned_state.set_storage_at(0, contract_address, key, stark_felt!(23_u8));
    versioned_state.set_nonce_at(0, contract_address, nonce);
    versioned_state.set_class_hash_at(0, contract_address, class_hash);
    versioned_state.set_compiled_class_hash(0, class_hash, compiled_class_hash);

    // Write new data.
    let compiled_class_hash_v5 = CompiledClassHash(stark_felt!(100_u8));
    versioned_state.set_compiled_class_hash(5, class_hash, compiled_class_hash_v5);

    let compiled_class_hash_v3 = CompiledClassHash(stark_felt!(5_u8));
    versioned_state.set_compiled_class_hash(3, class_hash, compiled_class_hash_v3);

    // Invalid read set.
    let entry = StorageEntry {
        arg: Box::new((contract_address, key)),
        storage_type: StorageType::Storage,
        value: Box::new(stark_felt!(2_u8)),
    };
    let read_set: &[StorageEntry] = &[entry];
    assert!(!validate_read_set(0, read_set, &mut versioned_state));

    let entry_1 = StorageEntry {
        arg: Box::new((contract_address, key)),
        storage_type: StorageType::Storage,
        value: Box::new(stark_felt!(23_u8)),
    };
    let entry_2 = StorageEntry {
        arg: Box::new(contract_address),
        storage_type: StorageType::Nonce,
        value: Box::new(nonce),
    };
    let entry_3 = StorageEntry {
        arg: Box::new(class_hash),
        storage_type: StorageType::CompiledClassHash,
        value: Box::new(compiled_class_hash),
    };
    let read_set: &[StorageEntry] = &[entry_1, entry_2, entry_3];
    assert!(validate_read_set(0, read_set, &mut versioned_state));

    let entry_1 = StorageEntry {
        arg: Box::new(contract_address),
        storage_type: StorageType::Nonce,
        value: Box::new(nonce),
    };
    let entry_2 = StorageEntry {
        arg: Box::new(class_hash),
        storage_type: StorageType::CompiledClassHash,
        value: Box::new(compiled_class_hash_v3),
    };
    let read_set: &[StorageEntry] = &[entry_1, entry_2];
    assert!(validate_read_set(4, read_set, &mut versioned_state));

    let entry_1 = StorageEntry {
        arg: Box::new(contract_address),
        storage_type: StorageType::Nonce,
        value: Box::new(nonce),
    };
    let entry_2 = StorageEntry {
        arg: Box::new(class_hash),
        storage_type: StorageType::CompiledClassHash,
        value: Box::new(compiled_class_hash_v5),
    };
    let read_set: &[StorageEntry] = &[entry_1, entry_2];
    assert!(validate_read_set(12, read_set, &mut versioned_state));
}
