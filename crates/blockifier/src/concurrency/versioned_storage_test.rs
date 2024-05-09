use std::collections::HashMap;

use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{class_hash, contract_address, patricia_key};

// use crate::concurrency::test_utils::contract_address;
use crate::concurrency::versioned_storage::VersionedStorage;
use crate::concurrency::TxIndex;

// TODO(barak, 01/07/2024): Split into test_read() and test_write().
#[test]
fn test_versioned_storage() {
    let mut storage = VersionedStorage::default();

    // Read an uninitialized cell.
    let value = storage.read(0, 1);
    assert!(value.is_none());

    // Set initial values.
    storage.set_initial_value(1, 31);
    storage.set_initial_value(5, 31);
    storage.set_initial_value(10, 31);

    // Write.
    storage.write(1, 1, 42);
    assert_eq!(storage.read(123, 1).unwrap(), 42);

    // Read initial value.
    assert_eq!(storage.read(1, 5).unwrap(), 31);

    // Read from the past.
    storage.write(2, 10, 78);
    assert_eq!(storage.read(1, 10).unwrap(), 31);
    // Ignore the value written by the current transaction.
    assert_eq!(storage.read(2, 10).unwrap(), 31);

    // Read uninitialized cell.
    assert!(storage.read(1, 100).is_none());

    // Write to uninitialized cell.
    storage.write(20, 100, 194);

    // Test the write.
    assert_eq!(storage.read(50, 100).unwrap(), 194);
}

#[rstest]
fn test_delete_writes(#[values(0, 1, 2)] tx_index_to_delete_writes: TxIndex) {
    // TODO(barak, 01/07/2025): Create a macro versioned_storage!.
    let mut class_hashes_versioned_storage = VersionedStorage::default();
    let contract_addresses = [contract_address!("0x100"), contract_address!("0x200")];
    let mut write_sets = vec![];
    for tx_index in 0..3 {
        let mut write_set: HashMap<&ContractAddress, ClassHash> = HashMap::default();
        for (i, contract_address) in contract_addresses.iter().enumerate() {
            let value = class_hash!(format!("0x{}", i).as_str());
            class_hashes_versioned_storage.write(tx_index, contract_address, value);
            write_set.insert(contract_address, value);
        }
        write_sets.push(write_set);
    }

    class_hashes_versioned_storage
        .delete_writes(write_sets[tx_index_to_delete_writes].keys(), tx_index_to_delete_writes);

    for tx_index in 0..3 {
        let should_contain_tx_index_writes = tx_index != tx_index_to_delete_writes;
        for contract_address in contract_addresses {
            assert_eq!(
                class_hashes_versioned_storage
                    .writes
                    .get(&contract_address)
                    .unwrap()
                    .contains_key(&tx_index),
                should_contain_tx_index_writes
            )
        }
    }
}
