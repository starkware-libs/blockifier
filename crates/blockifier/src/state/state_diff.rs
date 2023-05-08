use indexmap::IndexMap;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

/// Holds uncommitted changes induced on StarkNet contracts.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommitmentStateDiff {
    pub address_to_class_hash: IndexMap<ContractAddress, ClassHash>,
    pub storage_updates: IndexMap<ContractAddress, IndexMap<StorageKey, StarkFelt>>,
    pub class_hash_to_compiled_class_hash: IndexMap<ClassHash, CompiledClassHash>,
    pub address_to_nonce: IndexMap<ContractAddress, Nonce>,
}
