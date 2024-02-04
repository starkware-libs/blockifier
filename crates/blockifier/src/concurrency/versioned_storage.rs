use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::hash::Hash;

pub(crate) type Version = u64;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

/// A storage unit.
/// It is versioned in the sense that it holds a state of write operations done on it by
/// different versions of executions.
/// This allows maintaining the cells with the correct values in the context of each execution.
#[derive(Default)]
pub struct VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + Hash + Debug,
    V: Clone + Debug,
{
    cached_initial_values: HashMap<K, V>,
    writes: HashMap<K, BTreeMap<Version, V>>,
}

impl<K, V> VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + Hash + Debug,
    V: Clone + Debug,
{
    pub fn new() -> Self {
        VersionedStorage { cached_initial_values: HashMap::new(), writes: HashMap::new() }
    }

    pub fn read(&self, version: Version, key: K) -> Option<V> {
        let value = self.writes.get(&key).and_then(|cell| cell.range(..=version).next_back());
        value.map(|(_, value)| value).or_else(|| self.cached_initial_values.get(&key)).cloned()
    }

    pub fn write(&mut self, version: Version, key: K, value: V) {
        let cell = self.writes.entry(key).or_default();
        cell.insert(version, value);
    }

    /// This method inserts the provided key-value pair into the cached initial values map.
    /// It is typically used when reading a value that is not found in the versioned storage. In
    /// such a scenario, the value is retrieved from the initial storage and written to the
    /// cached initial values for future references.
    pub fn set_initial_value(&mut self, key: K, value: V) {
        self.cached_initial_values.insert(key, value);
    }
}
