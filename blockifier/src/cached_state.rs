use std::collections::HashMap;

/// A read-only API for accessing StarkNet global state.
pub trait StateReader {
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, contract_address: i32) -> Option<&i32>;

    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&self, _contract_address: i32) -> &[u8] {
        unimplemented!();
    }

    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(&self, _contract_address: i32, _key: i32) -> Option<i32> {
        unimplemented!();
    }
}

pub struct DictReader {
    pub dict: HashMap<i32, i32>,
}

impl StateReader for DictReader {
    fn get_nonce_at(&self, contract_address: i32) -> Option<&i32> {
        self.dict.get(&contract_address)
    }
}

/// Holds read and write requests.
///
/// Writer functionality is built-in, whereas Reader functionality is injected through
/// initialization.
pub struct CachedState<SR: StateReader> {
    pub state_reader: SR,
    cache: StateCache,
}

impl<SR: StateReader> CachedState<SR> {
    pub fn new(state_reader: SR) -> Self {
        Self { state_reader, cache: StateCache::default() }
    }

    pub fn increment_nonce(&mut self, contract_address: i32) {
        let current_nonce = *self.get_nonce_at(contract_address).expect("TODO: deal with error");
        self.cache.update_nonce_writes(contract_address, current_nonce + 1)
    }

    pub fn get_nonce_at(&mut self, contract_address: i32) -> Option<&i32> {
        if self.cache.get_nonce(contract_address).is_none() {
            let nonce = self
                .state_reader
                .get_nonce_at(contract_address)
                .expect(&(contract_address.to_string() + " should have a nonce."));

            self.cache.update_nonce_initial_values(contract_address, *nonce);
        }
        self.cache.get_nonce(contract_address)
    }
}

/// Holds read and write requests.
// Invariant: can't delete keys from fields.
#[derive(Default)]
struct StateCache {
    _nonce_initial_values: HashMap<i32, i32>,
    _nonce_writes: HashMap<i32, i32>,
}

impl StateCache {
    pub fn update_nonce_writes(&mut self, contract_address: i32, nonce: i32) {
        self._nonce_writes.insert(contract_address, nonce);
    }

    pub fn update_nonce_initial_values(&mut self, contract_address: i32, nonce: i32) {
        self._nonce_initial_values.insert(contract_address, nonce);
    }

    /// Looks for the contract address key in the writes cache, then in the initial values.
    fn get_nonce(&self, contract_address: i32) -> Option<&i32> {
        self._nonce_writes
            .get(&contract_address)
            .or_else(|| self._nonce_initial_values.get(&contract_address))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn gets_nonce() {
        let contract_address = 0;
        let initial_nonce = 1;
        let mut state = CachedState::new(DictReader {
            dict: HashMap::from([(contract_address, initial_nonce)]),
        });
        assert_eq!(*state.get_nonce_at(0).unwrap(), 1)
    }

    #[test]
    fn increments_nonce() {
        let contract_address1 = 100;
        let contract_address2 = 200;
        let initial_nonce = 1;
        let mut state = CachedState::new(DictReader {
            dict: HashMap::from([
                (contract_address1, initial_nonce),
                (contract_address2, initial_nonce),
            ]),
        });
        state.increment_nonce(contract_address1);
        assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), 2);
        assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), 1);

        state.increment_nonce(contract_address1);
        assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), 3);
        assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), 1);

        state.increment_nonce(contract_address2);
        assert_eq!(*state.get_nonce_at(contract_address1).unwrap(), 3);
        assert_eq!(*state.get_nonce_at(contract_address2).unwrap(), 2);
    }
}
