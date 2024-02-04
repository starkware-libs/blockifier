use std::collections::{BTreeMap, HashMap};

pub(crate) type Version = u64;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

/// A storage unit.
/// It is versioned in the sense that it holds a state of read and writes operation done on it by
/// different versions of executions.
/// This allows maintaining the cells with the correct values in the context of each execution.
#[derive(Default)]
pub struct VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub cached_initial_value: HashMap<K, V>,
    pub writes: HashMap<K, BTreeMap<Version, V>>,
}

impl<K, V> VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub fn new() -> Self {
        VersionedStorage { cached_initial_value: HashMap::new(), writes: HashMap::new() }
    }

    pub fn read(&self, cell_id: K, version: Version) -> Option<V> {
        let value = self
            .writes
            .get(&cell_id)
            .and_then(|writes_map| writes_map.range(..=version).next_back());
        match value {
            Some((_, value)) => Some(value.clone()),
            None => self.cached_initial_value.get(&cell_id).cloned(),
        }
    }

    pub fn write(&mut self, cell_id: K, version: Version, value: V) {
        let writes_map = self.writes.entry(cell_id).or_default();
        writes_map.insert(version, value);
    }

    pub fn set_initial_value(&mut self, cell_id: K, value: V) {
        self.cached_initial_value.insert(cell_id, value);
    }
}
