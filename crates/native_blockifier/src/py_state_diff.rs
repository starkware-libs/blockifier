use std::collections::HashMap;
use std::convert::TryFrom;

use indexmap::IndexMap;
use pyo3::prelude::*;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::state::{ContractClass, StateDiff, StorageKey};

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::py_utils::PyFelt;

#[pyclass]
#[derive(FromPyObject)]
// TODO: Add support for returning the declared_classes to python.
pub struct PyStateDiff {
    #[pyo3(get)]
    pub address_to_class_hash: HashMap<PyFelt, PyFelt>,
    #[pyo3(get)]
    pub address_to_nonce: HashMap<PyFelt, PyFelt>,
    #[pyo3(get)]
    pub storage_updates: HashMap<PyFelt, HashMap<PyFelt, PyFelt>>,
}

impl PyStateDiff {
    pub fn with_declared_classes(
        self,
        declared_class_hash_to_class: HashMap<PyFelt, String>,
    ) -> NativeBlockifierResult<StateDiff> {
        let mut deployed_contracts: IndexMap<ContractAddress, ClassHash> = IndexMap::new();
        for (address, class_hash) in self.address_to_class_hash {
            let address = ContractAddress::try_from(address.0)?;
            let class_hash = ClassHash(class_hash.0);
            deployed_contracts.insert(address, class_hash);
        }

        let mut storage_diffs = IndexMap::new();
        for (address, storage_mapping) in self.storage_updates {
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

        // Deserialize contract classes.
        let mut declared_classes: IndexMap<ClassHash, ContractClass> = IndexMap::new();
        for (class_hash, raw_class) in declared_class_hash_to_class {
            let blockifier_contract_class: blockifier::execution::contract_class::ContractClass =
                serde_json::from_str(raw_class.as_str()).map_err(NativeBlockifierError::from)?;
            declared_classes
                .insert(ClassHash(class_hash.0), ContractClass::from(blockifier_contract_class));
        }

        let mut nonces = IndexMap::new();
        for (address, nonce) in self.address_to_nonce {
            let address = ContractAddress::try_from(address.0)?;
            let nonce = Nonce(nonce.0);
            nonces.insert(address, nonce);
        }

        Ok(StateDiff { deployed_contracts, storage_diffs, declared_classes, nonces })
    }
}

impl From<StateDiff> for PyStateDiff {
    fn from(state_diff: StateDiff) -> Self {
        let mut address_to_class_hash = HashMap::<PyFelt, PyFelt>::new();
        for (address, class_hash) in state_diff.deployed_contracts {
            address_to_class_hash.insert(PyFelt::from(address), PyFelt(class_hash.0));
        }
        let mut address_to_nonce = HashMap::<PyFelt, PyFelt>::new();
        for (address, nonce) in state_diff.nonces {
            address_to_nonce.insert(PyFelt::from(address), PyFelt(nonce.0));
        }

        let mut storage_updates = HashMap::<PyFelt, HashMap<PyFelt, PyFelt>>::new();
        for (address, storage_diff) in state_diff.storage_diffs {
            let mut updates_at = HashMap::<PyFelt, PyFelt>::new();
            for (key, value) in storage_diff {
                updates_at.insert(PyFelt(*key.0.key()), PyFelt(value));
            }
            storage_updates.insert(PyFelt::from(address), updates_at);
        }

        Self { address_to_class_hash, address_to_nonce, storage_updates }
    }
}

#[derive(FromPyObject)]
pub struct PyBlockInfo {
    pub block_number: u64,
    pub block_timestamp: u64,
    pub gas_price: u128,
    pub sequencer_address: PyFelt,
}
