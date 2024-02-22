use std::any::Any;

use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use super::versioned_state::VersionedState;
use super::versioned_storage::Version;

#[cfg(test)]
#[path = "validator_test.rs"]
pub mod test;

pub struct StorageEntry {
    arg: Box<dyn Any>,
    storage_type: StorageType,
    value: Box<dyn Any>,
}

pub enum StorageType {
    Storage,
    Nonce,
    ClassHash,
    CompiledClassHash,
}

pub struct Validator;

impl Validator {
    // Define a method to validate read set against versioned state
    pub fn validate_read_set(
        &self,
        version: Version,
        read_set: &[StorageEntry],
        versioned_state: &mut VersionedState,
    ) -> bool {
        // Iterate through each entry in the read set
        for read in read_set {
            match read.storage_type {
                StorageType::Storage => {
                    let arg = read.arg.downcast_ref::<(ContractAddress, StorageKey)>().expect(
                        "Failed to downcast read value to a tuple of (ContractAddress, StorageKey)",
                    );
                    let value = versioned_state.get_storage_at(arg.0, arg.1, version);
                    assert!(value.is_ok());
                    let read_value = read
                        .value
                        .downcast_ref::<StarkFelt>()
                        .expect("Failed to downcast read value to StarkFelt");
                    if read_value != value.unwrap() {
                        return false;
                    }
                }
                StorageType::Nonce => {
                    let arg = read
                        .arg
                        .downcast_ref::<ContractAddress>()
                        .expect("Failed to downcast read value to ContractAddress");
                    let value = versioned_state.get_nonce_at(*arg, version);
                    assert!(value.is_ok());
                    let read_value = read
                        .value
                        .downcast_ref::<Nonce>()
                        .expect("Failed to downcast read value to Nonce");
                    if read_value != value.unwrap() {
                        return false;
                    }
                }
                StorageType::ClassHash => {
                    let arg = read
                        .arg
                        .downcast_ref::<ContractAddress>()
                        .expect("Failed to downcast read value to ContractAddress");
                    let value = versioned_state.get_class_hash_at(*arg, version);
                    assert!(value.is_ok());
                    let read_value = read
                        .value
                        .downcast_ref::<ClassHash>()
                        .expect("Failed to downcast read value to ClassHash");
                    if read_value != value.unwrap() {
                        return false;
                    }
                }
                StorageType::CompiledClassHash => {
                    let arg = read
                        .arg
                        .downcast_ref::<ClassHash>()
                        .expect("Failed to downcast read value to ClassHash");
                    let value = versioned_state.get_compiled_class_hash_at(*arg, version);
                    assert!(value.is_ok());
                    let read_value = read
                        .value
                        .downcast_ref::<CompiledClassHash>()
                        .expect("Failed to downcast read value to CompiledClassHash");
                    if read_value != value.unwrap() {
                        return false;
                    }
                }
            };
        }
        // All values in the read set match the values from versioned state, return true.
        true
    }
}
