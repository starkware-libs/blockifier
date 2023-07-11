use std::collections::HashMap;
use std::convert::TryFrom;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CommitmentStateDiff;
use indexmap::IndexMap;
use pyo3::prelude::*;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::state::{StateDiff, StorageKey};

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::py_block_executor::PyGeneralConfig;
use crate::py_utils::PyFelt;

#[pyclass]
#[derive(FromPyObject)]
// TODO: Add support for returning the `declared_classes` to python.
pub struct PyStateDiff {
    #[pyo3(get)]
    pub address_to_class_hash: HashMap<PyFelt, PyFelt>,
    #[pyo3(get)]
    pub address_to_nonce: HashMap<PyFelt, PyFelt>,
    #[pyo3(get)]
    pub storage_updates: HashMap<PyFelt, HashMap<PyFelt, PyFelt>>,
    #[pyo3(get)]
    pub class_hash_to_compiled_class_hash: HashMap<PyFelt, PyFelt>,
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

        let mut nonces = IndexMap::new();
        for (address, nonce) in state_diff.address_to_nonce {
            let address = ContractAddress::try_from(address.0)?;
            let nonce = Nonce(nonce.0);
            nonces.insert(address, nonce);
        }

        Ok(Self {
            deployed_contracts,
            storage_diffs,
            declared_classes: IndexMap::new(),
            deprecated_declared_classes: IndexMap::new(),
            nonces,
            replaced_classes: IndexMap::new(),
        })
    }
}

impl From<CommitmentStateDiff> for PyStateDiff {
    fn from(state_diff: CommitmentStateDiff) -> Self {
        // State commitment.
        let address_to_class_hash = state_diff
            .address_to_class_hash
            .iter()
            .map(|(address, class_hash)| (PyFelt::from(*address), PyFelt::from(*class_hash)))
            .collect();

        let address_to_nonce = state_diff
            .address_to_nonce
            .iter()
            .map(|(address, nonce)| (PyFelt::from(*address), PyFelt(nonce.0)))
            .collect();

        let storage_updates = state_diff
            .storage_updates
            .iter()
            .map(|(address, storage_diff)| {
                (
                    PyFelt::from(*address),
                    storage_diff
                        .iter()
                        .map(|(key, value)| (PyFelt(*key.0.key()), PyFelt(*value)))
                        .collect(),
                )
            })
            .collect();

        // Declared classes commitment
        let class_hash_to_compiled_class_hash = state_diff
            .class_hash_to_compiled_class_hash
            .iter()
            .map(|(class_hash, compiled_class_hash)| {
                (PyFelt::from(*class_hash), PyFelt::from(*compiled_class_hash))
            })
            .collect();

        Self {
            address_to_class_hash,
            address_to_nonce,
            storage_updates,
            class_hash_to_compiled_class_hash,
        }
    }
}

#[derive(FromPyObject)]
pub struct PyBlockInfo {
    pub block_number: u64,
    pub block_timestamp: u64,
    pub gas_price: u128,
    pub sequencer_address: PyFelt,
}

impl PyBlockInfo {
    pub fn into_block_context(
        self,
        general_config: &PyGeneralConfig,
        max_recursion_depth: usize,
    ) -> NativeBlockifierResult<BlockContext> {
        let starknet_os_config = &general_config.starknet_os_config;
        let block_number = BlockNumber(self.block_number);
        let block_context = BlockContext {
            chain_id: starknet_os_config.chain_id.clone(),
            block_number,
            block_timestamp: BlockTimestamp(self.block_timestamp),
            sequencer_address: ContractAddress::try_from(general_config.sequencer_address.0)?,
            fee_token_address: ContractAddress::try_from(starknet_os_config.fee_token_address.0)?,
            vm_resource_fee_cost: general_config.cairo_resource_fee_weights.clone(),
            gas_price: self.gas_price,
            invoke_tx_max_n_steps: general_config.invoke_tx_max_n_steps,
            validate_max_n_steps: general_config.validate_max_n_steps,
            max_recursion_depth,
        };

        Ok(block_context)
    }
}
