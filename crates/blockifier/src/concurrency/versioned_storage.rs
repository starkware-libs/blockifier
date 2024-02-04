use std::collections::{BTreeMap, HashMap};

pub(crate) type Version = u64;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

/// A storage unit.
/// It is versioned in the sense that it holds a state of write operation done on it by
/// different versions of executions.
/// This allows maintaining the cells with the correct values in the context of each execution.
#[derive(Default)]
pub struct VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub cached_initial_values: HashMap<K, V>,
    pub writes: HashMap<K, BTreeMap<Version, V>>,
}

impl<K, V> VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub fn new() -> Self {
        VersionedStorage { cached_initial_values: HashMap::new(), writes: HashMap::new() }
    }

    pub fn read(&self, version: Version, key: K) -> Option<V> {
        let value =
            self.writes.get(&key).and_then(|writes_map| writes_map.range(..=version).next_back());
        match value {
            Some((_, value)) => Some(value.clone()),
            None => self.cached_initial_values.get(&key).cloned(),
        }
    }

    pub fn write(&mut self, version: Version, key: K, value: V) {
        let cell = self.writes.entry(key).or_default();
        cell.insert(version, value);
    }

    pub fn set_initial_value(&mut self, key: K, value: V) {
        self.cached_initial_values.insert(key, value);
    }
}
