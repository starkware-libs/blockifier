use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use indexmap::IndexMap;
use papyrus_storage::compiled_class::CasmStorageWriter;
use papyrus_storage::header::{HeaderStorageReader, HeaderStorageWriter};
use papyrus_storage::state::{StateStorageReader, StateStorageWriter};
use pyo3::prelude::*;
use starknet_api::block::{BlockHash, BlockHeader, BlockNumber};
use starknet_api::core::{ChainId, ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;
use starknet_api::state::{ContractClass, StateDiff, StateNumber};

use crate::errors::NativeBlockifierResult;
use crate::py_state_diff::PyBlockInfo;
use crate::py_utils::{int_to_chain_id, PyFelt};
use crate::PyStateDiff;

const GENESIS_BLOCK_ID: u64 = u64::MAX;

// Invariant: Only one instance of this struct should exist.
// Reader and writer fields must be cleared before the struct goes out of scope in Python;
// to prevent possible memory leaks (TODO: see if this is indeed necessary).
pub struct Storage {
    reader: Option<papyrus_storage::StorageReader>,
    writer: Option<papyrus_storage::StorageWriter>,
}

impl Storage {
    pub fn new(config: StorageConfig) -> NativeBlockifierResult<Storage> {
        log::debug!("Initializing Blockifier storage...");
        let db_config = papyrus_storage::db::DbConfig {
            path_prefix: config.path_prefix,
            chain_id: config.chain_id,
            min_size: 1 << 20, // 1MB.
            max_size: config.max_size,
            growth_step: 1 << 26, // 64MB.
        };
        let storage_config = papyrus_storage::StorageConfig {
            db_config,
            scope: papyrus_storage::StorageScope::StateOnly, // Only stores blockifier-related data.
            // Storage for large objects (state-diffs, contracts). This sets total storage
            // allocated, maximum space an object can take, and how fast the storage grows.
            mmap_file_config: papyrus_storage::mmap_file::MmapFileConfig {
                max_size: 1 << 40,        // 1TB
                growth_step: 2 << 30,     // 2GB
                max_object_size: 1 << 30, // 1GB
            },
        };
        let (reader, writer) = papyrus_storage::open_storage(storage_config)?;
        log::debug!("Initialized Blockifier storage.");
        let db_stats = reader.db_tables_stats().expect("Failed to get db tables stats.");
        log::debug!(
            "Papyrus storage stats (open storage): {}",
            serde_json::to_string_pretty(&db_stats).expect("Failed to serialize table stats.")
        );

        // read storage diffs to see if it affects the first write transaction.
        {
            let txn = reader.begin_ro_txn().expect("Failed to begin read-only transaction.");
            let state_marker = txn.get_state_marker().expect("Failed to get state marker.");
            let state_number = StateNumber(state_marker);
            let last_state_diff =
                txn.get_state_diff(state_marker.prev().unwrap()).unwrap().unwrap();
            let state_reader = txn.get_state_reader().expect("Failed to get state reader.");

            for (contract_address, storage_diffs) in last_state_diff.storage_diffs.iter() {
                for (key, _) in storage_diffs.iter() {
                    state_reader.get_storage_at(state_number, contract_address, key).unwrap();
                }
            }
        }

        Ok(Storage { reader: Some(reader), writer: Some(writer) })
    }

    /// Manually drops the storage reader and writer.
    /// Python does not necessarily drop them even if instance is no longer live.
    pub fn close(&mut self) {
        log::debug!("Closing Blockifier storage.");
        self.reader = None;
        self.writer = None;
    }

    /// Returns the next block number, for which state diff was not yet appended.
    pub fn get_state_marker(&self) -> NativeBlockifierResult<u64> {
        let block_number = self.reader().begin_ro_txn()?.get_state_marker()?;
        Ok(block_number.0)
    }

    pub fn get_header_marker(&self) -> NativeBlockifierResult<u64> {
        let block_number = self.reader().begin_ro_txn()?.get_header_marker()?;
        Ok(block_number.0)
    }

    pub fn get_block_id(&self, block_number: u64) -> NativeBlockifierResult<Option<Vec<u8>>> {
        let block_number = BlockNumber(block_number);
        let block_hash = self
            .reader()
            .begin_ro_txn()?
            .get_block_header(block_number)?
            .map(|block_header| Vec::from(block_header.block_hash.0.bytes()));
        Ok(block_hash)
    }

    pub fn revert_block(&mut self, block_number: u64) -> NativeBlockifierResult<()> {
        log::debug!("Reverting state diff for {block_number:?}.");
        let block_number = BlockNumber(block_number);
        let revert_txn = self.writer().begin_rw_txn()?;
        let (revert_txn, _) = revert_txn.revert_state_diff(block_number)?;
        let (revert_txn, _) = revert_txn.revert_header(block_number)?;

        revert_txn.commit()?;
        Ok(())
    }

    // TODO(Gilad): Refactor.
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
        let state_number = StateNumber(block_number);

        let n_classes = declared_class_hash_to_class.len();
        log::debug!(
            "<{block_number}, 111> Collecting undeclared deprecated classes ({n_classes} \
             deprecated classes)."
        );
        // Deserialize contract classes.
        let mut deprecated_declared_classes = IndexMap::<ClassHash, DeprecatedContractClass>::new();
        for (i, (class_hash, raw_class)) in
            deprecated_declared_class_hash_to_class.iter().enumerate()
        {
            let class_hash = ClassHash(class_hash.0);
            log::debug!(
                "<{block_number}, 111, {i}> Checking if deprecated class {class_hash} is \
                 undeclared."
            );
            let class_undeclared = self
                .reader()
                .begin_ro_txn()?
                .get_state_reader()?
                .get_deprecated_class_definition_at(state_number, &class_hash)?
                .is_none();
            log::debug!(
                "<{block_number}, 111, {i}> Done fetching class {class_hash}. Is undeclared: \
                 {class_undeclared}."
            );

            if class_undeclared {
                log::debug!(
                    "<{block_number}, 111, {i}> Deprecated class {} is undeclared. Deserializing \
                     (raw_class.len() = {}).",
                    class_hash.0,
                    raw_class.len()
                );
                let deprecated_contract_class: DeprecatedContractClass =
                    serde_json::from_str(raw_class)?;
                log::debug!("<{block_number}, 111, {i}> Done deserializing class {class_hash}.");
                deprecated_declared_classes.insert(class_hash, deprecated_contract_class);
            }
        }
        let n_addresses = py_state_diff.address_to_class_hash.len();
        log::debug!(
            "<{block_number}, 111> Done collecting undeclared deprecated classes ({} total). \
             <{block_number}, 222> Collecting replaced classes ({n_addresses} addresses).",
            deprecated_declared_classes.len()
        );

        // Collect replaced classes (changed class hash of an already allocated address;
        // i.e.: pointing to a non-zeroed class hash). Rest would be (newly) deployed classes.
        let mut replaced_classes = IndexMap::<ContractAddress, ClassHash>::new();
        for (i, (address, class_hash)) in py_state_diff.address_to_class_hash.iter().enumerate() {
            let address = ContractAddress::try_from(address.0)?;
            log::debug!("<{block_number}, 222, {i}> Checking if address {address:?} is replaced.");
            let address_assigned: bool = self
                .reader()
                .begin_ro_txn()?
                .get_state_reader()?
                .get_class_hash_at(state_number, &address)?
                .is_some();
            log::debug!(
                "<{block_number}, 222, {i}> Done fetching class hash of address {address:?}. Is \
                 replaced: {address_assigned}."
            );

            if address_assigned {
                replaced_classes.insert(address, ClassHash(class_hash.0));
            }
        }
        let mut py_state_diff = py_state_diff;
        replaced_classes.keys().for_each(|&address| {
            py_state_diff.address_to_class_hash.remove(&address.into());
        });
        let n_classes = declared_class_hash_to_class.len();
        log::debug!(
            "<{block_number}, 222> Done collecting replaced classes ({} total). <{block_number}, \
             333> Collecting casms of undeclared classes ({n_classes} classes).",
            replaced_classes.len()
        );

        let mut declared_classes = IndexMap::<ClassHash, (CompiledClassHash, ContractClass)>::new();
        let mut undeclared_casm_contracts = Vec::<(ClassHash, CasmContractClass)>::new();
        for (i, (class_hash, (compiled_class_hash, raw_class))) in
            declared_class_hash_to_class.iter().enumerate()
        {
            let class_hash = ClassHash(class_hash.0);
            log::debug!("<{block_number}, 333, {i}> Checking if class {class_hash} is undeclared.");
            let class_undeclared = self
                .reader()
                .begin_ro_txn()?
                .get_state_reader()?
                .get_class_definition_at(state_number, &class_hash)?
                .is_none();
            log::debug!(
                "<{block_number}, 333, {i}> Done fetching class {class_hash}. Is undeclared: \
                 {class_undeclared}."
            );

            if class_undeclared {
                declared_classes.insert(
                    class_hash,
                    (CompiledClassHash(compiled_class_hash.0), ContractClass::default()),
                );
                log::debug!(
                    "<{block_number}, 333, {i}> Class {class_hash} is undeclared. Deserializing \
                     casm (raw_class.len() = {}).",
                    raw_class.len()
                );
                let contract_class: CasmContractClass = serde_json::from_str(raw_class)?;
                log::debug!("Done deserializing casm of class {class_hash}.");
                undeclared_casm_contracts.push((class_hash, contract_class));
            }
        }

        log::debug!(
            "<{block_number}, 333> Done collecting undeclared classes ({} total). \
             <{block_number}, 444> Writing the state diff to the storage.",
            undeclared_casm_contracts.len()
        );

        if block_id % 1000 == 0 {
            let table_stats =
                self.reader().db_tables_stats().expect("Failed to get db tables stats.");
            log::debug!(
                "<{block_number}, stats> Papyrus storage stats: {:?}",
                serde_json::to_string_pretty(&table_stats)
                    .expect("Failed to serialize table stats.")
            );
        }

        let mut append_txn = self.writer().begin_rw_txn()?;
        log::debug!(
            "<{block_number}, 444> Opened write transaction, appending casms ({} total).",
            undeclared_casm_contracts.len()
        );
        for (i, (class_hash, contract_class)) in undeclared_casm_contracts.iter().enumerate() {
            log::debug!("<{block_number}, 444, {i}> Appending casm of class {class_hash}.");
            append_txn = append_txn.append_casm(class_hash, contract_class)?;
            log::debug!("<{block_number}, 444, {i}> Done appending casm of class {class_hash}.");
        }

        // Construct state diff; manually add declared classes.
        log::debug!(
            "<{block_number}, 444> Done appending casms. <{block_number}, 555> Constructing state \
             diff.",
        );
        let mut state_diff = StateDiff::try_from(py_state_diff)?;
        state_diff.deprecated_declared_classes = deprecated_declared_classes;
        state_diff.declared_classes = declared_classes;
        state_diff.replaced_classes = replaced_classes;

        let n_changed_contracts = state_diff.storage_diffs.len();
        let mut n_total_changes = 0;
        for storage_diff in state_diff.storage_diffs.values() {
            n_total_changes += storage_diff.len();
        }

        let deployed_contract_class_definitions =
            IndexMap::<ClassHash, DeprecatedContractClass>::new();
        log::debug!(
            "<{block_number}, 555> Done constructing state diff, appending to storage \
             ***({n_changed_contracts} contracts changed, {n_total_changes}total changes)***"
        );
        append_txn = append_txn.append_state_diff(
            block_number,
            state_diff,
            deployed_contract_class_definitions,
        )?;
        log::debug!(
            "<{block_number}, 555> Done appending state diff to storage. <{block_number}, 666> \
             Appending header to storage."
        );

        let previous_block_id = previous_block_id.unwrap_or_else(|| PyFelt::from(GENESIS_BLOCK_ID));
        let block_header = BlockHeader {
            block_hash: BlockHash(StarkHash::from(block_id)),
            parent_hash: BlockHash(previous_block_id.0),
            block_number,
            ..Default::default()
        };
        append_txn = append_txn.append_header(block_number, &block_header)?;
        log::debug!(
            "<{block_number}, 666> Done appending header to storage. <{block_number}, 777> \
             Committing write transaction."
        );

        append_txn.commit()?;
        log::debug!("<{block_number}, 777> Done committing write transaction.");
        Ok(())
    }

    pub fn new_for_testing(path_prefix: PathBuf, chain_id: &ChainId) -> Storage {
        let db_config = papyrus_storage::db::DbConfig {
            path_prefix,
            chain_id: chain_id.clone(),
            min_size: 1 << 20,    // 1MB
            max_size: 1 << 35,    // 32GB
            growth_step: 1 << 26, // 64MB
        };
        let storage_config = papyrus_storage::StorageConfig { db_config, ..Default::default() };
        let (reader, writer) = papyrus_storage::open_storage(storage_config).unwrap();

        Storage { reader: Some(reader), writer: Some(writer) }
    }

    pub fn validate_aligned(&self, source_block_number: u64) {
        let header_marker = self.get_header_marker().expect("Should have a header marker");
        let state_marker = self.get_state_marker().expect("Should have a state marker");

        assert_eq!(
            header_marker, state_marker,
            "Block header marker ({header_marker}) must be aligned to block state diff marker \
             ({state_marker}) before sequencing starts."
        );

        assert_eq!(
            state_marker, source_block_number,
            "Target storage (block number {state_marker}) should have been aligned to block \
             number {source_block_number}."
        );
    }

    pub fn reader(&self) -> &papyrus_storage::StorageReader {
        self.reader.as_ref().expect("Storage should be initialized.")
    }

    pub fn writer(&mut self) -> &mut papyrus_storage::StorageWriter {
        self.writer.as_mut().expect("Storage should be initialized.")
    }
}

#[pyclass]
#[derive(Clone)]
pub struct StorageConfig {
    path_prefix: PathBuf,
    chain_id: ChainId,
    max_size: usize,
}

#[pymethods]
impl StorageConfig {
    #[new]
    #[pyo3(signature = (path_prefix, chain_id, max_size))]
    pub fn new(
        path_prefix: PathBuf,
        #[pyo3(from_py_with = "int_to_chain_id")] chain_id: ChainId,
        max_size: usize,
    ) -> Self {
        Self { path_prefix, chain_id, max_size }
    }
}
