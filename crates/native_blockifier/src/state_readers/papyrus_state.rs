use blockifier::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use papyrus_storage::compiled_class::CasmStorageReader;
use papyrus_storage::db::RO;
use papyrus_storage::state::StateStorageReader;
use papyrus_storage::StorageReader;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{StateNumber, StorageKey};

#[cfg(test)]
#[path = "papyrus_state_test.rs"]
mod test;

type RawPapyrusReader<'env> = papyrus_storage::StorageTxn<'env, RO>;

pub struct PapyrusReader {
    storage_reader: StorageReader,
    latest_block: BlockNumber,
}

impl PapyrusReader {
    pub fn new(storage_reader: StorageReader, latest_block: BlockNumber) -> Self {
        Self { storage_reader, latest_block }
    }

    fn reader(&self) -> StateResult<RawPapyrusReader<'_>> {
        self.storage_reader
            .begin_ro_txn()
            .map_err(|error| StateError::StateReadError(error.to_string()))
    }
}

// Currently unused - will soon replace the same `impl` for `PapyrusStateReader`.
impl StateReader for PapyrusReader {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let state_number = StateNumber(self.latest_block);
        self.reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_storage_at(state_number, &contract_address, &key))
            .map_err(|error| StateError::StateReadError(error.to_string()))
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let state_number = StateNumber(self.latest_block);
        match self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_nonce_at(state_number, &contract_address))
        {
            Ok(Some(nonce)) => Ok(nonce),
            Ok(None) => Ok(Nonce::default()),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let state_number = StateNumber(self.latest_block);
        match self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_class_hash_at(state_number, &contract_address))
        {
            Ok(Some(class_hash)) => Ok(class_hash),
            Ok(None) => Ok(ClassHash::default()),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }

    /// Returns a V1 contract if found, or a V0 contract if a V1 contract is not
    /// found, or an `Error` otherwise.
    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<ContractClass> {
        let state_number = StateNumber(self.latest_block);
        let class_declaration_block_number = self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_class_definition_block_number(class_hash))
            .map_err(|err| StateError::StateReadError(err.to_string()))?;
        let class_is_declared: bool = matches!(class_declaration_block_number,
                    Some(block_number) if block_number <= state_number.0);

        if class_is_declared {
            let casm_contract_class = self
                .reader()?
                .get_casm(class_hash)
                .map_err(|err| StateError::StateReadError(err.to_string()))?
                .expect(
                    "Should be able to fetch a Casm class if its definition exists, database is \
                     inconsistent.",
                );

            return Ok(ContractClass::V1(ContractClassV1::try_from(casm_contract_class)?));
        }

        let v0_contract_class = self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_deprecated_class_definition_at(state_number, class_hash))
            .map_err(|err| StateError::StateReadError(err.to_string()))?;

        match v0_contract_class {
            Some(starknet_api_contract_class) => {
                Ok(ContractClassV0::try_from(starknet_api_contract_class)?.into())
            }
            None => Err(StateError::UndeclaredClassHash(*class_hash)),
        }
    }

    fn get_compiled_class_hash(
        &mut self,
        _class_hash: ClassHash,
    ) -> StateResult<CompiledClassHash> {
        todo!()
    }
}
