use std::collections::hash_map::Entry;
use std::collections::HashMap;

use blockifier::execution::contract_class::{ContractClass, ContractClassV0};
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use papyrus_storage::db::RO;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{StateNumber, StorageKey};

#[cfg(test)]
#[path = "papyrus_state_test.rs"]
mod test;

pub type ClassCache = HashMap<ClassHash, ContractClass>;
type RawPapyrusStateReader<'env> = papyrus_storage::state::StateReader<'env, RO>;

pub struct PapyrusStateReader<'env> {
    pub reader: RawPapyrusStateReader<'env>,
    pub contract_class_cache: ClassCache,
    // Invariant: Read-Only.
    latest_block: BlockNumber,
}

impl<'env> PapyrusStateReader<'env> {
    pub fn new(
        reader: RawPapyrusStateReader<'env>,
        latest_block: BlockNumber,
        contract_class_cache: ClassCache,
    ) -> Self {
        Self { reader, latest_block, contract_class_cache }
    }

    pub fn latest_block(&self) -> &BlockNumber {
        &self.latest_block
    }
}

impl<'env> StateReader for PapyrusStateReader<'env> {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let state_number = StateNumber(*self.latest_block());
        self.reader
            .get_storage_at(state_number, &contract_address, &key)
            .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let state_number = StateNumber(*self.latest_block());
        match self.reader.get_nonce_at(state_number, &contract_address) {
            Ok(Some(nonce)) => Ok(nonce),
            Ok(None) => Ok(Nonce::default()),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let state_number = StateNumber(*self.latest_block());
        match self.reader.get_class_hash_at(state_number, &contract_address) {
            Ok(Some(class_hash)) => Ok(class_hash),
            Ok(None) => Ok(ClassHash::default()),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }

    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        let state_number = StateNumber(*self.latest_block());
        match self.contract_class_cache.entry(*class_hash) {
            Entry::Occupied(contract_class) => Ok(contract_class.get().clone()),
            Entry::Vacant(entry) => {
                match self.reader.get_deprecated_class_definition_at(state_number, class_hash) {
                    Ok(Some(starknet_api_contract_class)) => {
                        let contract_class =
                            ContractClassV0::try_from(starknet_api_contract_class)?.into();
                        Ok(entry.insert(contract_class).clone())
                    }
                    Ok(None) => Err(StateError::UndeclaredClassHash(*class_hash)),
                    Err(err) => Err(StateError::StateReadError(err.to_string())),
                }
            }
        }
    }

    fn get_compiled_class_hash(
        &mut self,
        _class_hash: ClassHash,
    ) -> StateResult<CompiledClassHash> {
        todo!()
    }
}
