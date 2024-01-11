use std::fmt;
use std::time::Instant;

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
    pub timer: PapyrusReaderTimer,
}

impl PapyrusReader {
    pub fn new(storage_reader: StorageReader, latest_block: BlockNumber) -> Self {
        let timer = PapyrusReaderTimer::default();
        Self { storage_reader, latest_block, timer }
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
        let start_time = Instant::now();
        let storage = self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_storage_at(state_number, &contract_address, &key))
            .map_err(|error| StateError::StateReadError(error.to_string()));
        let end_time = start_time.elapsed();
        self.timer.get_storage_time += end_time.as_nanos();
        self.timer.total_time += end_time.as_nanos();
        storage
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let state_number = StateNumber(self.latest_block);
        let start_time = Instant::now();
        let result = self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_nonce_at(state_number, &contract_address));
        let end_time = start_time.elapsed();
        self.timer.get_nonce_at_time += end_time.as_nanos();
        self.timer.total_time += end_time.as_nanos();
        match result {
            Ok(Some(nonce)) => Ok(nonce),
            Ok(None) => Ok(Nonce::default()),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let state_number = StateNumber(self.latest_block);
        let start_time = Instant::now();
        let result = self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_class_hash_at(state_number, &contract_address));
        let end_time = start_time.elapsed();
        self.timer.get_class_hash_at_time += end_time.as_nanos();
        self.timer.total_time += end_time.as_nanos();
        match result {
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
        let start_time = Instant::now();
        let class_declaration_block_number = self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_class_definition_block_number(class_hash))
            .map_err(|err| StateError::StateReadError(err.to_string()))?;
        let end_time = start_time.elapsed();
        self.timer.get_class_definition_block_number_time += end_time.as_nanos();
        self.timer.total_time += end_time.as_nanos();
        let class_is_declared: bool = matches!(class_declaration_block_number,
                    Some(block_number) if block_number <= state_number.0);

        if class_is_declared {
            let start_time = Instant::now();
            let casm_contract_class = self
                .reader()?
                .get_casm(class_hash)
                .map_err(|err| StateError::StateReadError(err.to_string()))?
                .expect(
                    "Should be able to fetch a Casm class if its definition exists, database is \
                     inconsistent.",
                );
            let end_time = start_time.elapsed();
            self.timer.get_casm_time += end_time.as_nanos();
            self.timer.total_time += end_time.as_nanos();

            return Ok(ContractClass::V1(ContractClassV1::try_from(casm_contract_class)?));
        }

        let v0_contract_class = self
            .reader()?
            .get_state_reader()
            .and_then(|sr| sr.get_deprecated_class_definition_at(state_number, class_hash))
            .map_err(|err| StateError::StateReadError(err.to_string()))?;
        let end_time = start_time.elapsed();
        self.timer.get_deprecated_class_definition_at_time += end_time.as_nanos();
        self.timer.total_time += end_time.as_nanos();

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

#[derive(Clone, Copy, Debug, Default)]
pub struct PapyrusReaderTimer {
    pub get_storage_time: u128,
    pub get_nonce_at_time: u128,
    pub get_class_hash_at_time: u128,
    pub get_class_definition_block_number_time: u128,
    pub get_deprecated_class_definition_at_time: u128,
    pub get_casm_time: u128,
    pub total_time: u128,
}
impl fmt::Display for PapyrusReaderTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "get_storage time: {} nanoseconds\nget_nonce_at time: {} \
             nanoseconds\nget_class_hash_at time: {} \
             nanoseconds\nget_class_definition_block_number time: {} \
             nanoseconds\nget_deprecated_class_definition_at time: {} nanoseconds\nget_casm time: \
             {} nanoseconds\nTotal time: {} nanoseconds",
            self.get_storage_time,
            self.get_nonce_at_time,
            self.get_class_hash_at_time,
            self.get_class_definition_block_number_time,
            self.get_deprecated_class_definition_at_time,
            self.get_casm_time,
            self.total_time
        )
    }
}
