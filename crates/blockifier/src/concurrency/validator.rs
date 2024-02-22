use std::sync::{Arc, Mutex};

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::concurrency::versioned_state::VersionedState;
use crate::concurrency::versioned_storage::Version;
use crate::execution::contract_class::ContractClass;
use crate::state::state_api::StateReader;

#[cfg(test)]
#[path = "validator_test.rs"]
pub mod test;

pub enum StorageArgument {
    StorageAt(ContractAddress, StorageKey, StarkFelt),
    NonceAt(ContractAddress, Nonce),
    ClassHashAt(ContractAddress, ClassHash),
    CompiledClassHash(ClassHash, CompiledClassHash),
    ContractClass(ClassHash, ContractClass),
}

pub fn validate_read_set<S: StateReader>(
    version: Version,
    read_set: &[StorageArgument],
    versioned_state: &mut VersionedState<S>,
) -> bool {
    // Iterate through each entry in the read set
    for read in read_set {
        match read {
            StorageArgument::StorageAt(contract_address, storage_key, expected_value) => {
                let value =
                    versioned_state.get_storage_at(version, *contract_address, *storage_key);
                assert!(value.is_ok());
                if expected_value != &value.unwrap() {
                    return false;
                }
            }
            StorageArgument::NonceAt(contract_address, expected_value) => {
                let value = versioned_state.get_nonce_at(version, *contract_address);
                assert!(value.is_ok());
                if expected_value != &value.unwrap() {
                    return false;
                }
            }
            StorageArgument::ClassHashAt(contract_address, expected_value) => {
                let value = versioned_state.get_class_hash_at(version, *contract_address);
                assert!(value.is_ok());
                if expected_value != &value.unwrap() {
                    return false;
                }
            }
            StorageArgument::CompiledClassHash(class_hash, expected_value) => {
                let value = versioned_state.get_compiled_class_hash(version, *class_hash);
                assert!(value.is_ok());
                if expected_value != &value.unwrap() {
                    return false;
                }
            }
            StorageArgument::ContractClass(class_hash, expected_value) => {
                let value = versioned_state.get_compiled_contract_class(version, *class_hash);
                assert!(value.is_ok());
                if expected_value != &value.unwrap() {
                    return false;
                }
            }
        }
    }
    // All values in the read set match the values from versioned state, return true.
    true
}

pub fn transaction_commit<S: StateReader>(
    version: Version,
    write_set: &[StorageArgument],
    versioned_state: &mut Arc<Mutex<VersionedState<S>>>,
) {
    // Iterate through each entry in the write set
    for write in write_set {
        match write {
            StorageArgument::StorageAt(contract_address, storage_key, value) => {
                versioned_state.lock().unwrap().set_storage_at(
                    version,
                    *contract_address,
                    *storage_key,
                    *value,
                );
            }
            StorageArgument::NonceAt(contract_address, value) => {
                versioned_state.lock().unwrap().set_nonce_at(version, *contract_address, *value);
            }
            StorageArgument::ClassHashAt(contract_address, value) => {
                versioned_state.lock().unwrap().set_class_hash_at(
                    version,
                    *contract_address,
                    *value,
                );
            }
            StorageArgument::CompiledClassHash(class_hash, value) => {
                versioned_state.lock().unwrap().set_compiled_class_hash(
                    version,
                    *class_hash,
                    *value,
                );
            }
            StorageArgument::ContractClass(class_hash, value) => {
                versioned_state.lock().unwrap().set_compiled_contract_class(
                    version,
                    *class_hash,
                    value.clone(),
                );
            }
        }
    }
}
