use blockifier::execution::contract_class::{ContractClass, ContractClassV0};
use blockifier::state::errors::StateError;
use blockifier::state::state_api::{StateReader, StateResult};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use papyrus_storage::casm::CasmStorageReader;
use papyrus_storage::db::RO;
use papyrus_storage::StorageResult;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{StateNumber, StorageKey};

#[cfg(test)]
#[path = "papyrus_state_test.rs"]
mod test;

type RawPapyrusStateReader<'env> = papyrus_storage::state::StateReader<'env, RO>;

pub struct PapyrusReader<'env> {
    state: PapyrusStateReader<'env>,
    contracts: PapyrusContractReader<'env>,
}

impl<'env> PapyrusReader<'env> {
    pub fn new(state: PapyrusStateReader<'env>, contracts: PapyrusContractReader<'env>) -> Self {
        Self { state, contracts }
    }
}

pub struct PapyrusStateReader<'env> {
    pub reader: RawPapyrusStateReader<'env>,
    // Invariant: Read-Only.
    latest_block: BlockNumber,
}

impl<'env> PapyrusStateReader<'env> {
    pub fn new(reader: RawPapyrusStateReader<'env>, latest_block: BlockNumber) -> Self {
        Self { reader, latest_block }
    }

    pub fn latest_block(&self) -> &BlockNumber {
        &self.latest_block
    }
}

impl<'env> StateReader for PapyrusReader<'env> {
    fn get_storage_at(
        &mut self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        let state_number = StateNumber(*self.state.latest_block());
        self.state
            .reader
            .get_storage_at(state_number, &contract_address, &key)
            .map_err(|err| StateError::StateReadError(err.to_string()))
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        let state_number = StateNumber(*self.state.latest_block());
        match self.state.reader.get_nonce_at(state_number, &contract_address) {
            Ok(Some(nonce)) => Ok(nonce),
            Ok(None) => Ok(Nonce::default()),
            Err(err) => Err(StateError::StateReadError(err.to_string())),
        }
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        let state_number = StateNumber(*self.state.latest_block());
        match self.state.reader.get_class_hash_at(state_number, &contract_address) {
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
        let v1_contract_class = self
            .contracts
            .get_casm(*class_hash)
            .map_err(|err| StateError::StateReadError(err.to_string()))?;

        if let Some(casm_contract_class) = v1_contract_class {
            return Ok(ContractClass::V1(casm_contract_class));
        }

        let state_number = StateNumber(*self.state.latest_block());
        let v0_contract_class = self
            .state
            .reader
            .get_deprecated_class_definition_at(state_number, class_hash)
            .map_err(|err| StateError::StateReadError(err.to_string()))?;

        match v0_contract_class {
            Some(starknet_api_contract_class) => {
                Ok(ContractClass::V0(ContractClassV0::try_from(starknet_api_contract_class)?))
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

pub struct PapyrusContractReader<'env> {
    // txn: &'env DbTransaction<'env, RO>,
    txn: &'env papyrus_storage::StorageTxn<'env, RO>,
}

impl<'env> PapyrusContractReader<'env> {
    pub fn new(txn: &'env papyrus_storage::StorageTxn<'env, RO>) -> Self {
        Self { txn }
    }
    fn get_casm(&self, class_hash: ClassHash) -> StorageResult<Option<CasmContractClass>> {
        self.txn.get_casm(class_hash)
    }
}
