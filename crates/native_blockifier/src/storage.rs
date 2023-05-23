use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;

use indexmap::IndexMap;
use papyrus_storage::header::{HeaderStorageReader, HeaderStorageWriter};
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockHeader, BlockNumber, BlockTimestamp, GasPrice};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, GlobalRoot};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;
use starknet_api::state::{ContractClass, StateDiff, StateNumber};

use crate::errors::NativeBlockifierResult;
use crate::py_state_diff::PyBlockInfo;
use crate::py_utils::PyFelt;
use crate::PyStateDiff;

const GENESIS_BLOCK_ID: u64 = u64::MAX;

#[pyclass]
// Invariant: Only one instance of this struct should exist.
// Reader and writer fields must be cleared before the struct goes out of scope in Python;
// to prevent possible memory leaks (TODO: see if this is indeed necessary).
pub struct Storage {
    reader: Option<papyrus_storage::StorageReader>,
    writer: Option<papyrus_storage::StorageWriter>,
}

#[pymethods]
impl Storage {
    #[new]
    #[args(path, max_size)]
    pub fn new(path: PathBuf, max_size: usize) -> NativeBlockifierResult<Storage> {
        log::debug!("Initializing Blockifier storage...");
        let db_config = papyrus_storage::db::DbConfig {
            path,
            min_size: 1 << 20, // 1MB.
            max_size,
            growth_step: 1 << 26, // 64MB.
        };
        let (reader, writer) = papyrus_storage::open_storage(db_config)?;
        log::debug!("Initialized Blockifier storage.");

        Ok(Storage { reader: Some(reader), writer: Some(writer) })
    }

    /// Manually drops the storage reader and writer.
    /// Python does not necessarily drop them even if instance is no longer live.
    pub fn close(&mut self) {
        self.reader = None;
        self.writer = None;
    }

    /// Returns the next block number, for which state diff was not yet appended.
    pub fn get_state_marker(&self) -> NativeBlockifierResult<u64> {
        let block_number = self.reader().begin_ro_txn()?.get_state_marker()?;
        Ok(block_number.0)
    }

    /// Returns the next block number, for which block header was not yet appended.
    /// Block header stream is usually ahead of the state diff stream, so this is the indicative
    /// marker.
    pub fn get_header_marker(&self) -> NativeBlockifierResult<u64> {
        let block_number = self.reader().begin_ro_txn()?.get_header_marker()?;
        Ok(block_number.0)
    }

    #[args(block_number)]
    /// Returns the unique identifier of the given block number in bytes.
    pub fn get_block_id(&self, block_number: u64) -> NativeBlockifierResult<Option<Vec<u8>>> {
        let block_number = BlockNumber(block_number);
        let block_hash = self
            .reader()
            .begin_ro_txn()?
            .get_block_header(block_number)?
            .map(|block_header| Vec::from(block_header.block_hash.0.bytes()));
        Ok(block_hash)
    }

    /// Atomically reverts block header and state diff of given block number.
    /// If header exists without a state diff (usually the case), only the header is reverted.
    /// (this is true for every partial existence of information at tables).
    #[args(block_number)]
    pub fn revert_block(&mut self, block_number: u64) -> NativeBlockifierResult<()> {
        log::debug!("Reverting state diff for {block_number:?}.");
        let block_number = BlockNumber(block_number);
        let revert_txn = self.writer().begin_rw_txn()?;
        let (revert_txn, _) = revert_txn.revert_state_diff(block_number)?;
        let (revert_txn, _) = revert_txn.revert_header(block_number)?;

        revert_txn.commit()?;
        Ok(())
    }

    #[args(
        block_id,
        previous_block_id,
        py_block_info,
        py_state_diff,
        declared_class_hash_to_class,
        deprecated_declared_class_hash_to_class
    )]
    /// Appends state diff and block header into Papyrus storage.
    // Previous block ID can either be a block hash (starting from a Papyrus snapshot), or a
    // sequential ID (throughout sequencing).
    pub fn append_block(
        &mut self,
        block_id: u64,
        previous_block_id: Option<PyFelt>,
        py_block_info: PyBlockInfo,
        py_state_diff: PyStateDiff,
        declared_class_hash_to_class: HashMap<PyFelt, (PyFelt, String)>,
        deprecated_declared_class_hash_to_class: HashMap<PyFelt, String>,
    ) -> NativeBlockifierResult<()> {
        log::debug!(
            "Appending state diff with {block_id:?} for block_number: {}.",
            py_block_info.block_number
        );
        let block_number = BlockNumber(py_block_info.block_number);

        // Deserialize contract classes.
        let mut deprecated_declared_classes: IndexMap<ClassHash, DeprecatedContractClass> =
            IndexMap::new();
        for (class_hash, raw_class) in deprecated_declared_class_hash_to_class {
            let class_hash = ClassHash(class_hash.0);
            let state_number = StateNumber(block_number);
            let class_undeclared = self
                .reader()
                .begin_ro_txn()?
                .get_state_reader()?
                .get_deprecated_class_definition_at(state_number, &class_hash)?
                .is_none();
            if class_undeclared {
                let deprecated_contract_class: DeprecatedContractClass =
                    serde_json::from_str(&raw_class)?;
                deprecated_declared_classes.insert(class_hash, deprecated_contract_class);
            }
        }
        let mut declared_classes: IndexMap<ClassHash, (CompiledClassHash, ContractClass)> =
            IndexMap::new();
        for (class_hash, (compiled_class_hash, raw_class)) in declared_class_hash_to_class {
            let contract_class: starknet_api::state::ContractClass =
                serde_json::from_str(&raw_class)?;
            declared_classes.insert(
                ClassHash(class_hash.0),
                (CompiledClassHash(compiled_class_hash.0), contract_class),
            );
        }

        // Construct state diff; manually add declared classes.
        let mut state_diff = StateDiff::try_from(py_state_diff)?;
        state_diff.deprecated_declared_classes = deprecated_declared_classes;
        state_diff.declared_classes = declared_classes;

        let deployed_contract_class_definitions =
            IndexMap::<ClassHash, DeprecatedContractClass>::new();
        let append_txn = self.writer().begin_rw_txn()?.append_state_diff(
            block_number,
            state_diff,
            deployed_contract_class_definitions,
        );
        let append_txn = append_txn?;

        let previous_block_id = previous_block_id.unwrap_or_else(|| PyFelt::from(GENESIS_BLOCK_ID));
        let block_header = BlockHeader {
            block_hash: BlockHash(StarkHash::from(block_id)),
            parent_hash: BlockHash(previous_block_id.0),
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
}

// Internal getters, Python should not have access to them, and only use the public API.
impl Storage {
    pub fn reader(&self) -> &papyrus_storage::StorageReader {
        self.reader.as_ref().expect("Storage should be initialized.")
    }
    pub fn writer(&mut self) -> &mut papyrus_storage::StorageWriter {
        self.writer.as_mut().expect("Storage should be initialized.")
    }
}
