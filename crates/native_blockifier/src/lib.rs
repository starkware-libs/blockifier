use std::collections::HashMap;
use std::convert::TryFrom;

use indexmap::IndexMap;
use papyrus_storage::db::DbConfig;
use papyrus_storage::header::HeaderStorageReader;
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use papyrus_storage::{open_storage, StorageReader, StorageWriter};
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{StateDiff, StorageKey};
use starknet_api::StarknetApiError;

pub type NativeBlockifierResult<T> = Result<T, NativeBlockifierError>;

#[pymodule]
fn native_blockifier(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<Storage>()?;

    m.add_function(wrap_pyfunction!(hello_world, m)?)?;
    m.add_function(wrap_pyfunction!(test_ret_value, m)?)?;
    m.add_function(wrap_pyfunction!(test_storage, m)?)?;
    m.add_function(wrap_pyfunction!(storage, m)?)?;

    Ok(())
}

#[pyclass]
pub struct Storage {
    pub reader: StorageReader,
    pub writer: StorageWriter,
}

#[pymethods]
impl Storage {
    pub fn get_state_marker(&self) -> NativeBlockifierResult<u64> {
        let block_number = self.reader.begin_ro_txn()?.get_state_marker()?;
        Ok(block_number.0)
    }

    pub fn get_block_hash(&self, block_number: u64) -> NativeBlockifierResult<Option<Vec<u8>>> {
        let block_number = BlockNumber(block_number);
        let block_hash = self
            .reader
            .begin_ro_txn()?
            .get_block_header(block_number)?
            .map(|block_header| Vec::from(block_header.block_hash.0.bytes()));
        Ok(block_hash)
    }

    // TODO: Do we want to return the stateDiff dropped?
    pub fn revert_state_diff(&mut self, block_number: u64) -> NativeBlockifierResult<()> {
        self.writer.begin_rw_txn()?.revert_state_diff(BlockNumber(block_number))?;
        Ok(())
    }

    pub fn append_state_diff(
        &mut self,
        block_number: u64,
        py_state_diff: &PyAny,
        _py_deployed_contract_class_definitions: &PyAny,
    ) -> NativeBlockifierResult<()> {
        let py_state_diff: PyStateDiff = py_state_diff.extract()?;
        let state_diff = StateDiff::try_from(py_state_diff)?;

        // TODO: This cast is tricky
        let deployed_contract_class_definitions = IndexMap::new();
        let block_number = BlockNumber(block_number);

        self.writer.begin_rw_txn()?.append_state_diff(
            block_number,
            state_diff,
            deployed_contract_class_definitions,
        )?;
        Ok(())
    }
}

#[derive(FromPyObject)]
pub struct PyStateDiff {
    pub address_to_class_hash: HashMap<u64, u64>,
    pub address_to_nonce: HashMap<u64, u64>,
    pub class_hash_to_compiled_class_hash: HashMap<u64, u64>,
    pub storage_updates: HashMap<u64, HashMap<u64, u64>>,
}

impl TryFrom<PyStateDiff> for StateDiff {
    type Error = NativeBlockifierError;

    fn try_from(state_diff: PyStateDiff) -> NativeBlockifierResult<Self> {
        let mut deployed_contracts = IndexMap::new();
        for (address, class_hash) in state_diff.address_to_class_hash {
            let contract_address = ContractAddress::try_from(StarkFelt::from(address))?;
            let class_hash = ClassHash(StarkFelt::from(class_hash));
            deployed_contracts.insert(contract_address, class_hash);
        }

        let mut storage_diffs = IndexMap::new();
        for (address, storage_mapping) in state_diff.storage_updates {
            let contract_address = ContractAddress::try_from(StarkFelt::from(address))?;
            storage_diffs.insert(contract_address, IndexMap::new());
            for (storage_key, storage_value) in storage_mapping {
                let storage_key = StorageKey::try_from(StarkFelt::from(storage_key))?;
                let storage_value = StarkFelt::from(storage_value);
                storage_diffs.entry(contract_address).and_modify(|map| {
                    map.insert(storage_key, storage_value);
                });
            }
        }

        // TODO: this isn't present in Python's state_diff, where do i get this from?
        let declared_classes = IndexMap::new();

        let mut nonces = IndexMap::new();
        for (address, nonce) in state_diff.address_to_nonce {
            let contract_address = ContractAddress::try_from(StarkFelt::from(address))?;
            let nonce = Nonce(StarkFelt::from(nonce));
            nonces.insert(contract_address, nonce);
        }

        Ok(Self { deployed_contracts, storage_diffs, declared_classes, nonces })
    }
}

#[pyfunction]
fn hello_world() {
    println!("Hello from rust.");
}

#[pyfunction]
fn test_ret_value(x: i32, y: i32) -> i32 {
    x + y
}

#[pyfunction]
fn test_storage() -> Storage {
    let (reader, writer) = papyrus_storage::test_utils::get_test_storage();

    Storage { reader, writer }
}

#[pyfunction]
fn storage(path: String) -> NativeBlockifierResult<Storage> {
    let db_config = DbConfig {
        path,
        max_size: 1 << 35, // 32GB.
    };

    let (reader, writer) = open_storage(db_config)?;
    Ok(Storage { reader, writer })
}

#[derive(thiserror::Error, Debug)]
pub enum NativeBlockifierError {
    #[error(transparent)]
    StorageError(#[from] papyrus_storage::StorageError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    Pyo3Error(#[from] PyErr),
}

impl From<NativeBlockifierError> for PyErr {
    fn from(err: NativeBlockifierError) -> PyErr {
        PyOSError::new_err(err.to_string())
    }
}
