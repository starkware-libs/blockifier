use std::collections::HashMap;
use std::convert::TryFrom;

use blockifier::bouncer::BouncerWeights;
use blockifier::state::cached_state::CommitmentStateDiff;
use blockifier::test_utils::{
    DEFAULT_ETH_L1_DATA_GAS_PRICE, DEFAULT_ETH_L1_GAS_PRICE, DEFAULT_STRK_L1_DATA_GAS_PRICE,
    DEFAULT_STRK_L1_GAS_PRICE,
};
use indexmap::IndexMap;
use pyo3::prelude::*;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::state::{StateDiff, StorageKey};

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
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

#[derive(Default, FromPyObject)]
pub struct PyResourcePrice {
    pub price_in_wei: u128,
    pub price_in_fri: u128,
}

#[derive(Clone, Debug, FromPyObject)]
pub struct PyBouncerConfig {
    pub full_total_weights_with_keccak: HashMap<String, usize>,
    pub full_total_weights: HashMap<String, usize>,
}

impl PyBouncerConfig {
    pub fn create_for_testing() -> Self {
        Self {
            full_total_weights_with_keccak: BouncerWeights::create_for_testing(true).into(),
            full_total_weights: BouncerWeights::create_for_testing(false).into(),
        }
    }
}

#[derive(FromPyObject)]
pub struct PyBlockInfo {
    pub block_number: u64,
    pub block_timestamp: u64,
    pub bouncer_config: PyBouncerConfig,
    pub l1_gas_price: PyResourcePrice,
    pub l1_data_gas_price: PyResourcePrice,
    pub sequencer_address: PyFelt,
    pub use_kzg_da: bool,
}

/// Block info cannot have gas prices set to zero; implement `Default` explicitly.
impl PyBlockInfo {
    pub fn create_for_testing() -> Self {
        Self {
            block_number: u64::default(),
            block_timestamp: u64::default(),
            bouncer_config: PyBouncerConfig::create_for_testing(),
            l1_gas_price: PyResourcePrice {
                price_in_wei: DEFAULT_ETH_L1_GAS_PRICE,
                price_in_fri: DEFAULT_STRK_L1_GAS_PRICE,
            },
            l1_data_gas_price: PyResourcePrice {
                price_in_wei: DEFAULT_ETH_L1_DATA_GAS_PRICE,
                price_in_fri: DEFAULT_STRK_L1_DATA_GAS_PRICE,
            },
            sequencer_address: PyFelt::default(),
            use_kzg_da: bool::default(),
        }
    }
}
