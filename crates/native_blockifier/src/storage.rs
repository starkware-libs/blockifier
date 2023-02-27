use std::collections::HashMap;
use std::convert::TryFrom;

use indexmap::IndexMap;
use papyrus_storage::header::{HeaderStorageReader, HeaderStorageWriter};
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockHeader, BlockNumber, BlockTimestamp, GasPrice};
use starknet_api::core::{ClassHash, ContractAddress, GlobalRoot};
use starknet_api::hash::StarkHash;
use starknet_api::state::ContractClass;

use crate::errors::NativeBlockifierResult;
use crate::py_state_diff::PyBlockInfo;
use crate::py_utils::PyFelt;
use crate::PyStateDiff;

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

    /// Returns the next block number (the one that was not yet created).
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

    #[args(block_numbers)]
    pub fn revert_state_diffs(&mut self, block_numbers: Vec<u64>) -> NativeBlockifierResult<()> {
        for block_number in block_numbers.into_iter() {
            self.revert_state_diff(block_number)?;
        }
        Ok(())
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

    #[args(append_state_diff_configs)]
    /// Revert state diffs in reverse order to the given range.
    pub fn append_state_diffs(
        &mut self,
        append_state_diff_configs: Vec<AppendStateDiffConfig>,
    ) -> NativeBlockifierResult<()> {
        for config in append_state_diff_configs.into_iter() {
            self.append_state_diff(config)?;
        }
        Ok(())
    }

    #[args(config)]
    /// Appends state diff and block header into Papyrus storage.
    pub fn append_state_diff(
        &mut self,
        config: AppendStateDiffConfig,
    ) -> NativeBlockifierResult<()> {
        let block_number = BlockNumber(config.py_block_info.block_number);

        // Construct state diff; manually add declared classes.
        let state_diff =
            config.py_state_diff.with_declared_classes(config.declared_class_hash_to_class)?;

        let deployed_contract_class_definitions = IndexMap::<ClassHash, ContractClass>::new();
        let append_txn = self.writer.begin_rw_txn()?.append_state_diff(
            block_number,
            state_diff,
            deployed_contract_class_definitions,
        );
        let append_txn = append_txn?;

        let block_header = BlockHeader {
            block_hash: BlockHash(StarkHash::from(config.block_id)),
            parent_hash: BlockHash(StarkHash::from(config.previous_block_id)),
            block_number,
            gas_price: GasPrice(config.py_block_info.gas_price),
            state_root: GlobalRoot::default(),
            sequencer: ContractAddress::try_from(config.py_block_info.sequencer_address.0)?,
            timestamp: BlockTimestamp(config.py_block_info.block_timestamp),
        };
        let append_txn = append_txn.append_header(block_number, &block_header)?;

        append_txn.commit()?;
        Ok(())
    }
}

#[derive(FromPyObject)]
pub struct AppendStateDiffConfig {
    pub block_id: u64,
    pub previous_block_id: u64,
    #[pyo3(attribute("block_info"))]
    pub py_block_info: PyBlockInfo,
    #[pyo3(attribute("state_diff"))]
    pub py_state_diff: PyStateDiff,
    pub declared_class_hash_to_class: HashMap<PyFelt, String>,
}
