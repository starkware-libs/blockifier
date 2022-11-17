use std::collections::HashMap;

use anyhow::{ensure, Context, Result};
use starknet_api::{
    ClassHash, ContractAddress, ContractNonce, Nonce, StarkHash, StorageEntry, StorageKey,
};

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<&ContractNonce>;

    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&self, _contract_address: ContractAddress) -> Result<&ClassHash> {
        unimplemented!();
    }

    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(
        &self,
        _contract_address: ContractAddress,
        _key: StorageKey,
    ) -> Result<&StorageEntry> {
        unimplemented!();
    }
}

pub struct DictReader {
    pub dict: HashMap<ContractAddress, ContractNonce>,
}

impl StateReader for DictReader {
    fn get_nonce_at(&self, contract_address: ContractAddress) -> Result<&ContractNonce> {
        self.dict
            .get(&contract_address)
            .with_context(|| format!("{:?} should have a nonce.", contract_address))
    }
}

/// Holds read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    _cache: StateCache,
}

impl<SR: StateReader> CachedState<SR> {
    pub fn new(state_reader: SR) -> Self {
        Self { state_reader, _cache: StateCache::default() }
    }

    pub fn increment_nonce(&mut self, contract_address: ContractAddress) -> Result<()> {
        let current_nonce = &mut self.get_nonce_at(contract_address)?.nonce;
        let incremented_nonce = u64_try_from_starkhash(&current_nonce.0)? + 1_u64;

        *current_nonce = nonce_from_u64(incremented_nonce);
        Ok(())
    }

    pub fn get_nonce_at(
        &mut self,
        contract_address: ContractAddress,
    ) -> Result<&mut ContractNonce> {
        if self._cache.get_nonce(contract_address).is_none() {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self._cache.try_insert_nonce_initial_value(&contract_address, nonce)?;
        }

        self._cache
            .get_nonce(contract_address)
            .ok_or_else(|| panic!("Cache can't retrieve contract address: {:?}", contract_address))
    }
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `TryFrom`
pub fn u64_try_from_starkhash(hash: &StarkHash) -> Result<u64> {
    let as_bytes: [u8; 8] = hash.bytes()[24..32].try_into()?;
    Ok(u64::from_be_bytes(as_bytes))
}

// TODO(Gilad, 1/12/2022): Move this to Starknet_api and convert to `From`
pub fn nonce_from_u64(num: u64) -> Nonce {
    Nonce(StarkHash::from(num))
}

/// Holds read and write requests.
// Invariant: can't delete keys from fields.
#[derive(Default)]
struct StateCache {
    _nonce_initial_values: HashMap<ContractAddress, ContractNonce>,
    _nonce_writes: HashMap<ContractAddress, ContractNonce>,
}

impl StateCache {
    pub fn try_insert_nonce_initial_value(
        &mut self,
        contract_address: &ContractAddress,
        nonce: &ContractNonce,
    ) -> Result<()> {
        ensure!(
            !self._nonce_initial_values.contains_key(contract_address),
            "contract_address {:?} already has initial nonce {:?}",
            contract_address,
            self._nonce_initial_values.get(contract_address)
        );
        self._nonce_initial_values.insert(*contract_address, nonce.clone());
        Ok(())
    }

    /// Looks for the contract address key in the writes cache, then in the initial values.
    fn get_nonce(&mut self, contract_address: ContractAddress) -> Option<&mut ContractNonce> {
        self._nonce_writes
            .get_mut(&contract_address)
            .or_else(|| self._nonce_initial_values.get_mut(&contract_address))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;
    use starknet_api::Nonce;

    use super::*;

    #[test]
    fn gets_nonce() -> Result<()> {
        let contract_address = ContractAddress::try_from(StarkHash::try_from(0)?)?;
        let initial_nonce = ContractNonce { contract_address, nonce: Nonce(StarkHash::from(1)) };
        let mut state = CachedState::new(DictReader {
            dict: HashMap::from([(contract_address, initial_nonce.clone())]),
        });
        assert_eq!(*state.get_nonce_at(contract_address).unwrap(), initial_nonce);
        Ok(())
    }

    #[test]
    fn increments_nonce() -> Result<()> {
        let contract_address1 = ContractAddress::try_from(StarkHash::try_from(100)?)?;
        let contract_address2 = ContractAddress::try_from(StarkHash::try_from(200)?)?;
        let initial_nonce1 =
            ContractNonce { contract_address: contract_address1, nonce: Nonce(StarkHash::from(1)) };
        let initial_nonce2 =
            ContractNonce { contract_address: contract_address2, nonce: Nonce(StarkHash::from(1)) };
        let mut state = CachedState::new(DictReader {
            dict: HashMap::from([
                (contract_address1, initial_nonce1),
                (contract_address2, initial_nonce2),
            ]),
        });

        state.increment_nonce(contract_address1)?;
        assert_eq!(state.get_nonce_at(contract_address1).unwrap().nonce, Nonce(StarkHash::from(2)));
        assert_eq!(state.get_nonce_at(contract_address2).unwrap().nonce, Nonce(StarkHash::from(1)));

        state.increment_nonce(contract_address1)?;
        assert_eq!(state.get_nonce_at(contract_address1).unwrap().nonce, Nonce(StarkHash::from(3)));
        assert_eq!(state.get_nonce_at(contract_address2).unwrap().nonce, Nonce(StarkHash::from(1)));

        state.increment_nonce(contract_address2)?;
        assert_eq!(state.get_nonce_at(contract_address1).unwrap().nonce, Nonce(StarkHash::from(3)));
        assert_eq!(state.get_nonce_at(contract_address2).unwrap().nonce, Nonce(StarkHash::from(2)));
        Ok(())
    }
}
