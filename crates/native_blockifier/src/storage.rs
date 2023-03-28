use std::collections::HashMap;
use std::convert::TryFrom;

use indexmap::IndexMap;
use num_bigint::{BigInt, Sign};
use papyrus_storage::header::{HeaderStorageReader, HeaderStorageWriter};
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockHeader, BlockNumber, BlockTimestamp, GasPrice};
use starknet_api::core::{ClassHash, ContractAddress, GlobalRoot};
use starknet_api::hash::StarkHash;
use starknet_api::state::{ContractClass, StateDiff};

use crate::errors::{
    NativeBlockifierError, NativeBlockifierResult, NativeBlockifierValidationError,
};
use crate::py_state_diff::PyBlockInfo;
use crate::py_utils::PyFelt;
use crate::PyStateDiff;

const GENESIS_BLOCK_ID: u64 = u64::MAX;

#[pyclass]
pub struct Storage {
    pub reader: papyrus_storage::StorageReader,
    pub writer: papyrus_storage::StorageWriter,
}

#[pymethods]
impl Storage {
    #[new]
    #[args(path, max_size)]
    pub fn new(path: String, max_size: usize) -> NativeBlockifierResult<Storage> {
        let db_config = papyrus_storage::db::DbConfig { path, max_size };
        let (reader, writer) = papyrus_storage::open_storage(db_config)?;
        Ok(Storage { reader, writer })
    }

    /// Returns the next block number (the one that was not yet created).
    pub fn get_state_marker(&self) -> NativeBlockifierResult<u64> {
        let block_number = self.reader.begin_ro_txn()?.get_state_marker()?;
        Ok(block_number.0)
    }

    #[args(block_number)]
    /// Returns the unique identifier of the given block number in bytes.
    pub fn get_block_id(&self, block_number: u64) -> NativeBlockifierResult<Option<Vec<u8>>> {
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
        let (revert_txn, _) = revert_txn.revert_header(block_number)?;

        revert_txn.commit()?;
        Ok(())
    }

    #[args(block_id, previous_block_id, py_block_info, py_state_diff, declared_class_hash_to_class)]
    /// Appends state diff and block header into Papyrus storage.
    pub fn append_state_diff(
        &mut self,
        block_id: u64,
        previous_block_id: Option<u64>,
        py_block_info: PyBlockInfo,
        py_state_diff: PyStateDiff,
        declared_class_hash_to_class: HashMap<PyFelt, String>,
    ) -> NativeBlockifierResult<()> {
        let block_number = BlockNumber(py_block_info.block_number);

        // Deserialize contract classes.
        let mut declared_classes: IndexMap<ClassHash, ContractClass> = IndexMap::new();
        for (class_hash, raw_class) in declared_class_hash_to_class {
            let blockifier_contract_class: blockifier::execution::contract_class::ContractClass =
                serde_json::from_str(raw_class.as_str()).map_err(NativeBlockifierError::from)?;
            declared_classes
                .insert(ClassHash(class_hash.0), ContractClass::from(blockifier_contract_class));
        }

        // Construct state diff; manually add declared classes.
        let mut state_diff = StateDiff::try_from(py_state_diff)?;
        state_diff.declared_classes = declared_classes;

        let deployed_contract_class_definitions = IndexMap::<ClassHash, ContractClass>::new();
        let append_txn = self.writer.begin_rw_txn()?.append_state_diff(
            block_number,
            state_diff,
            deployed_contract_class_definitions,
        );
        let append_txn = append_txn?;

        let previous_block_id = previous_block_id.unwrap_or(GENESIS_BLOCK_ID);
        let block_header = BlockHeader {
            block_hash: BlockHash(StarkHash::from(block_id)),
            parent_hash: BlockHash(StarkHash::from(previous_block_id)),
            block_number,
            gas_price: GasPrice(py_block_info.gas_price),
            state_root: GlobalRoot::default(),
            sequencer: ContractAddress::try_from(py_block_info.sequencer_address.0)?,
            timestamp: BlockTimestamp(py_block_info.block_timestamp),
        };
        let append_txn = append_txn.append_header(block_number, &block_header)?;

        append_txn.commit()?;
        Ok(())
    }

    #[args(latest_block_id)]
    pub fn validate_aligned(&self, latest_block_id: BigInt) -> NativeBlockifierResult<()> {
        let block_number = self.get_state_marker()? - 1;
        let block_id = self.get_block_id(block_number)?;
        let block_id = match block_id {
            Some(id) => BigInt::from_bytes_be(Sign::Plus, &id),
            None => BigInt::from(-1),
        };

        if block_id != latest_block_id {
            return Err(NativeBlockifierError::from(
                NativeBlockifierValidationError::StorageUnaligned {
                    blockifier_latest_block_id: block_id,
                    actual_latest_block_id: latest_block_id,
                },
            ));
        }

        Ok(())
    }
}
