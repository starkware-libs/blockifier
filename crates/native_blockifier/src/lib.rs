mod py_block_info;
pub mod py_state_diff;
pub mod py_transaction;
pub mod py_utils;

use std::convert::TryFrom;

use blockifier::transaction::errors::TransactionExecutionError;
use indexmap::IndexMap;
use papyrus_storage::header::{HeaderStorageReader, HeaderStorageWriter};
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use py_block_info::PyBlockInfo;
use py_transaction::PyTransactionExecutor;
use py_utils::PyFelt;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockHeader, BlockNumber, BlockTimestamp, GasPrice};
use starknet_api::core::{ClassHash, ContractAddress, GlobalRoot};
use starknet_api::state::{ContractClass, StateDiff};
use starknet_api::StarknetApiError;

use crate::py_state_diff::PyStateDiff;

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
    pub fn get_block_hash(&self, block_number: u64) -> NativeBlockifierResult<Option<Vec<u8>>> {
        let block_number = BlockNumber(block_number);
        let block_hash = self
            .reader
            .begin_ro_txn()?
            .get_block_header(block_number)?
            .map(|block_header| Vec::from(block_header.block_hash.0.bytes()));
        Ok(block_hash)
    }

    #[args(block_number)]
    pub fn revert_state_diff(&mut self, block_number: u64) -> NativeBlockifierResult<()> {
        let block_number = BlockNumber(block_number);
        let revert_txn = self.writer.begin_rw_txn()?;

        let (revert_txn, _) = revert_txn.revert_state_diff(block_number)?;
        let revert_txn = revert_txn.revert_header(block_number)?;
        revert_txn.commit()?;
        Ok(())
    }

    #[args(block_number, py_state_diff, _py_deployed_contract_class_definitions)]
    /// Appends state diff and block header into papyrus storage.
    pub fn append_state_diff(
        &mut self,
        block_id: PyFelt,
        previous_block_id: PyFelt,
        block_info: PyBlockInfo,
        py_state_diff: PyStateDiff,
        _py_deployed_contract_class_definitions: &PyAny,
    ) -> NativeBlockifierResult<()> {
        let block_number = BlockNumber(block_info.block_number);
        let state_diff = StateDiff::try_from(py_state_diff)?;
        // TODO: Figure out how to go from `py_state_diff.class_hash_to_compiled_class_hash` into
        // this type.
        let deployed_contract_class_definitions = IndexMap::<ClassHash, ContractClass>::new();

        let append_txn = self.writer.begin_rw_txn()?.append_state_diff(
            block_number,
            state_diff,
            deployed_contract_class_definitions,
        );
        let append_txn = append_txn?;

        let block_header = BlockHeader {
            block_hash: BlockHash(block_id.0),
            parent_hash: BlockHash(previous_block_id.0),
            block_number,
            gas_price: GasPrice(block_info.gas_price),
            state_root: GlobalRoot::default(),
            sequencer: ContractAddress::try_from(block_info.sequencer_address.0)?,
            timestamp: BlockTimestamp(block_info.block_timestamp),
        };
        let append_txn = append_txn.append_header(block_number, &block_header)?;

        append_txn.commit()?;
        Ok(())
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
