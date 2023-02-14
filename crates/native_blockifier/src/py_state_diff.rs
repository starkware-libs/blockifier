use std::collections::HashMap;
use std::convert::TryFrom;

use indexmap::IndexMap;
use pyo3::prelude::*;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::state::{StateDiff, StorageKey};

use super::{NativeBlockifierError, NativeBlockifierResult};
use crate::py_utils::PyFelt;

#[derive(FromPyObject)]
#[pyclass]
pub struct PyStateDiff {
    pub address_to_class_hash: HashMap<PyFelt, PyFelt>,
    pub address_to_nonce: HashMap<PyFelt, PyFelt>,
    pub class_hash_to_compiled_class_hash: HashMap<PyFelt, PyFelt>,
    pub storage_updates: HashMap<PyFelt, HashMap<PyFelt, PyFelt>>,
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

impl From<StateDiff> for PyStateDiff {
    fn from(value: StateDiff) -> Self {
        let mut address_to_class_hash: HashMap<PyFelt, PyFelt> = HashMap::new();
        let mut address_to_nonce: HashMap<PyFelt, PyFelt> = HashMap::new();
        let mut storage_updates: HashMap<PyFelt, HashMap<PyFelt, PyFelt>> = HashMap::new();
        for (address, class_hash) in value.deployed_contracts {
            address_to_class_hash.insert(address.into(), class_hash.into());
        }
        for (address, nonce) in value.nonces {
            address_to_nonce.insert(address.into(), nonce.into());
        }
        for (address, diffs) in value.storage_diffs {
            let mut updates_at_address = HashMap::new();
            for (key, felt) in diffs {
                updates_at_address.insert(key.into(), felt.into());
            }
            storage_updates.insert(address.into(), updates_at_address);
        }

        PyStateDiff {
            address_to_class_hash,
            address_to_nonce,
            class_hash_to_compiled_class_hash: HashMap::new(),
            storage_updates,
        }
    }
}
