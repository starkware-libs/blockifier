use std::collections::{BTreeMap, HashMap};

use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::core::{ClassHash, ContractAddress};

use crate::concurrency::test_utils::{class_hash, contract_address};
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
    // Include the value written by the current transaction.
    assert_eq!(storage.read(2, 10).unwrap(), 78);

    // Read uninitialized cell.
    assert!(storage.read(1, 100).is_none());

    // Write to uninitialized cell.
    storage.write(20, 100, 194);

    // Test the write.
    assert_eq!(storage.read(50, 100).unwrap(), 194);
}

#[rstest]
fn test_delete_write(
    contract_address: ContractAddress,
    class_hash: ClassHash,
    #[values(0, 1, 2)] tx_index_to_delete_writes: TxIndex,
) {
    // TODO(barak, 01/07/2025): Create a macro versioned_storage!.
    let num_of_txs = 3;
    let mut versioned_storage = VersionedStorage {
        cached_initial_values: HashMap::default(),
        writes: HashMap::from([(
            contract_address,
            // Class hash values are not checked in this test.
            BTreeMap::from_iter((0..num_of_txs).map(|i| (i, class_hash))),
        )]),
    };
    for tx_index in 0..num_of_txs {
        let should_contain_tx_index_writes = tx_index != tx_index_to_delete_writes;
        versioned_storage.delete_write(contract_address, tx_index_to_delete_writes);
        assert_eq!(
            versioned_storage.writes.get(&contract_address).unwrap().contains_key(&tx_index),
            should_contain_tx_index_writes
        )
    }
}
