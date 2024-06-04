use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::hash::Hash;

use crate::concurrency::TxIndex;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

/// A storage unit.
/// It is versioned in the sense that it holds a state of write operations done on it by
/// different versions of executions.
/// This allows maintaining the cells with the correct values in the context of each execution.
#[derive(Debug)]
pub struct VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + Hash + Debug,
    V: Clone + Debug,
{
    cached_initial_values: HashMap<K, V>,
    writes: HashMap<K, BTreeMap<TxIndex, V>>,
}

impl<K, V> Default for VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + Hash + Debug,
    V: Clone + Debug,
{
    fn default() -> Self {
        // We cannot derive `Default` since the derive requires that both `K` and `V` impl
        // `Default`.
        VersionedStorage { cached_initial_values: Default::default(), writes: Default::default() }
    }
}

impl<K, V> VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + Hash + Debug,
    V: Clone + Debug,
{
    pub fn read(&self, tx_index: TxIndex, key: K) -> Option<V> {
        // TODO: Ignore `ESTIMATE` values (when added).
        let value = self.writes.get(&key).and_then(|cell| cell.range(..=tx_index).next_back());
        value.map(|(_, value)| value).or_else(|| self.cached_initial_values.get(&key)).cloned()
    }

    pub fn write(&mut self, tx_index: TxIndex, key: K, value: V) {
        let cell = self.writes.entry(key).or_default();
        cell.insert(tx_index, value);
    }

    pub fn delete_write(&mut self, key: K, tx_index: TxIndex) {
        self.writes
            .get_mut(&key)
            .expect(
                "A 'delete_write' call must be preceded by a 'write' call with the corresponding \
                 key",
            )
            .remove(&tx_index);
    }

    /// This method inserts the provided key-value pair into the cached initial values map.
    /// It is typically used when reading a value that is not found in the versioned storage. In
    /// such a scenario, the value is retrieved from the initial storage and written to the
    /// cached initial values for future references.
    pub fn set_initial_value(&mut self, key: K, value: V) {
        self.cached_initial_values.insert(key, value);
    }

    pub(crate) fn get_writes_up_to_index(&self, index: TxIndex) -> HashMap<K, V> {
        let mut writes = HashMap::default();
        for (&key, cell) in self.writes.iter() {
            if let Some(value) = cell.range(..=index).next_back() {
                writes.insert(key, value.1.clone());
            }
        }
        writes
    }

    #[cfg(any(feature = "testing", test))]
    pub fn get_writes_of_index(&self, tx_index: TxIndex) -> HashMap<K, V> {
        let mut writes = HashMap::default();
        for (&key, cell) in self.writes.iter() {
            if let Some(value) = cell.get(&tx_index) {
                writes.insert(key, value.clone());
            }
        }
        writes
    }
}
