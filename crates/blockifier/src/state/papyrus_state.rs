use papyrus_storage::db::TransactionKind;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{StateNumber, StorageKey};

use crate::execution::contract_class::ContractClass;
use crate::state::errors::StateError;
use crate::state::state_api::{StateReader, StateResult};

#[cfg(test)]
#[path = "papyrus_state_test.rs"]
mod test;

type RawPapyrusStateReader<'env, Mode> = papyrus_storage::state::StateReader<'env, Mode>;

pub struct PapyrusStateReader<'env, Mode: TransactionKind> {
    pub reader: RawPapyrusStateReader<'env, Mode>,
    // Invariant: Read-Only.
    latest_block: BlockNumber,
}

impl<'env, Mode: TransactionKind> PapyrusStateReader<'env, Mode> {
    pub fn new(reader: RawPapyrusStateReader<'env, Mode>, latest_block: BlockNumber) -> Self {
        Self { reader, latest_block }
    }

    pub fn latest_block(&self) -> &BlockNumber {
        &self.latest_block
    }
}

impl<'env, Mode: TransactionKind> StateReader for PapyrusStateReader<'env, Mode> {
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

    fn get_contract_class(
        &mut self,
        class_hash: &starknet_api::core::ClassHash,
    ) -> StateResult<ContractClass> {
        let state_number = StateNumber(*self.latest_block());
        match self.reader.get_class_definition_at(state_number, class_hash) {
            Ok(Some(starknet_api_contract_class)) => {
                Ok(ContractClass::from(starknet_api_contract_class))
            }
            Ok(None) => Err(StateError::UndeclaredClassHash(*class_hash)),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }
}
