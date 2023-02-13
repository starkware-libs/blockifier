pub mod py_transaction;
pub mod py_utils;

use std::collections::HashMap;
use std::convert::TryFrom;

use blockifier::transaction::errors::TransactionExecutionError;
use indexmap::IndexMap;
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use py_transaction::PyTransactionExecutor;
use py_utils::PyFelt;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::state::{ContractClass, StateDiff, StorageKey};
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

#[pymodule]
fn native_blockifier(_py: Python<'_>, py_module: &PyModule) -> PyResult<()> {
    py_module.add_class::<PyStateDiff>()?;
    py_module.add_class::<PyTransactionExecutor>()?;
    py_module.add_class::<Storage>()?;

    Ok(())
}

#[pyclass]
pub struct Storage {
    pub reader: papyrus_storage::StorageReader,
    pub writer: papyrus_storage::StorageWriter,
}

#[pymethods]
impl Storage {
    #[new]
    #[args(path)]
    pub fn new(path: String) -> NativeBlockifierResult<Storage> {
        let db_config = papyrus_storage::db::DbConfig {
            path,
            max_size: 1 << 35, // 32GB.
        };

        let (reader, writer) = papyrus_storage::open_storage(db_config)?;
        Ok(Storage { reader, writer })
    }

    pub fn get_state_marker(&self) -> NativeBlockifierResult<u64> {
        let block_number = self.reader.begin_ro_txn()?.get_state_marker()?;
        Ok(block_number.0)
    }

    #[args(block_number)]
    pub fn get_state_diff(&self, block_number: u64) -> NativeBlockifierResult<Option<PyStateDiff>> {
        let block_number = BlockNumber(block_number);
        let thin_state_diff = self.reader.begin_ro_txn()?.get_state_diff(block_number)?;
        Ok(thin_state_diff.map(PyStateDiff::from))
    }

    #[args(block_number)]
    pub fn revert_state_diff(&mut self, block_number: u64) -> NativeBlockifierResult<()> {
        let (revert_txn, _) =
            self.writer.begin_rw_txn()?.revert_state_diff(BlockNumber(block_number))?;
        revert_txn.commit()?;
        Ok(())
    }

    #[args(block_number, py_state_diff, _py_deployed_contract_class_definitions)]
    pub fn append_state_diff(
        &mut self,
        block_number: u64,
        py_state_diff: PyStateDiff,
        _py_deployed_contract_class_definitions: &PyAny,
    ) -> NativeBlockifierResult<()> {
        let block_number = BlockNumber(block_number);
        let state_diff = StateDiff::try_from(py_state_diff)?;
        // TODO: Figure out how to go from `py_state_diff.class_hash_to_compiled_class_hash` into
        // this type.
        let deployed_contract_class_definitions = IndexMap::<ClassHash, ContractClass>::new();

        let append_txn = self.writer.begin_rw_txn()?.append_state_diff(
            block_number,
            state_diff,
            deployed_contract_class_definitions,
        );
        append_txn?.commit()?;
        Ok(())
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyStateDiff {
    #[pyo3(get)]
    pub address_to_class_hash: HashMap<PyFelt, PyFelt>,
    #[pyo3(get)]
    pub address_to_nonce: HashMap<PyFelt, PyFelt>,
    #[pyo3(get)]
    pub declared_contract_hashes: Vec<PyFelt>,
    #[pyo3(get)]
    pub storage_updates: HashMap<PyFelt, HashMap<PyFelt, PyFelt>>,
}

#[pymethods]
impl PyStateDiff {
    #[new]
    pub fn new(
        address_to_class_hash: HashMap<PyFelt, PyFelt>,
        address_to_nonce: HashMap<PyFelt, PyFelt>,
        declared_contract_hashes: Vec<PyFelt>,
        storage_updates: HashMap<PyFelt, HashMap<PyFelt, PyFelt>>,
    ) -> NativeBlockifierResult<PyStateDiff> {
        Ok(PyStateDiff {
            address_to_class_hash,
            address_to_nonce,
            declared_contract_hashes,
            storage_updates,
        })
    }
}

impl TryFrom<PyStateDiff> for StateDiff {
    type Error = NativeBlockifierError;

    fn try_from(state_diff: PyStateDiff) -> NativeBlockifierResult<Self> {
        let mut deployed_contracts: IndexMap<ContractAddress, ClassHash> = IndexMap::new();
        for (address, class_hash) in state_diff.address_to_class_hash {
            let address = ContractAddress::try_from(address.0)?;
            let class_hash = ClassHash(class_hash.0);
            deployed_contracts.insert(address, class_hash);
        }

        let mut storage_diffs = IndexMap::new();
        for (address, storage_mapping) in state_diff.storage_updates {
            let address = ContractAddress::try_from(address.0)?;
            storage_diffs.insert(address, IndexMap::new());

            for (key, value) in storage_mapping {
                let storage_key = StorageKey::try_from(key.0)?;
                let storage_value = value.0;
                storage_diffs.entry(address).and_modify(|changes| {
                    changes.insert(storage_key, storage_value);
                });
            }
        }

        let declared_classes = IndexMap::new();
        let mut nonces = IndexMap::new();
        for (address, nonce) in state_diff.address_to_nonce {
            let address = ContractAddress::try_from(address.0)?;
            let nonce = Nonce(nonce.0);
            nonces.insert(address, nonce);
        }

        Ok(Self { deployed_contracts, storage_diffs, declared_classes, nonces })
    }
}

impl From<papyrus_storage::state::data::ThinStateDiff> for PyStateDiff {
    fn from(state_diff: papyrus_storage::state::data::ThinStateDiff) -> Self {
        let mut address_to_class_hash = HashMap::<PyFelt, PyFelt>::new();
        for (address, class_hash) in state_diff.deployed_contracts {
            address_to_class_hash.insert(PyFelt::from(address), PyFelt(class_hash.0));
        }
        let mut address_to_nonce = HashMap::<PyFelt, PyFelt>::new();
        for (address, nonce) in state_diff.nonces {
            address_to_nonce.insert(PyFelt::from(address), PyFelt(nonce.0));
        }
        let declared_contract_hashes = state_diff
            .declared_contract_hashes
            .iter()
            .map(|&class_hash| PyFelt(class_hash.0))
            .collect();

        let mut storage_updates = HashMap::<PyFelt, HashMap<PyFelt, PyFelt>>::new();
        for (address, storage_diff) in state_diff.storage_diffs {
            let felt_address = PyFelt::from(address);
            for (key, value) in storage_diff {
                let storage_key = *key.0.key();
                storage_updates.entry(felt_address).and_modify(|changes| {
                    changes.insert(PyFelt(storage_key), PyFelt(value));
                });
            }
        }

        Self { address_to_class_hash, address_to_nonce, declared_contract_hashes, storage_updates }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NativeBlockifierError {
    #[error(transparent)]
    Pyo3Error(#[from] PyErr),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    TransactionExecutionError(#[from] TransactionExecutionError),
    #[error(transparent)]
    StorageError(#[from] papyrus_storage::StorageError),
}

impl From<NativeBlockifierError> for PyErr {
    fn from(error: NativeBlockifierError) -> PyErr {
        match error {
            NativeBlockifierError::Pyo3Error(py_error) => py_error,
            _ => PyOSError::new_err(error.to_string()),
        }
    }
}
