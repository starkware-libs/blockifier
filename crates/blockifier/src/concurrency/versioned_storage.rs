use std::collections::{BTreeMap, HashMap};

use crate::state::errors::StateError;
use crate::state::state_api::StateResult;

pub(crate) type Version = u64;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

pub type ReadCallback<K, V> = dyn Fn(K) -> Option<V>;

/// A storage unit.
/// It is versioned in the sense that it holds a state of read and writes operation done on it by
/// different versions of executions.
/// This allows maintaining the cells with the correct values in the context of each execution.
pub struct VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub base_value_read_callback: Box<ReadCallback<K, V>>,
    pub writes: HashMap<K, BTreeMap<Version, V>>,
}

impl<K, V> VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub fn new(base_value_read_callback: Box<ReadCallback<K, V>>) -> Self {
        VersionedStorage { base_value_read_callback, writes: HashMap::new() }
    }

    pub fn read(&self, cell_id: K, version: Version) -> StateResult<V> {
        let value = self
            .writes
            .get(&cell_id)
            .and_then(|writes_map| writes_map.range(..=version).next_back());
        match value {
            Some((_, value)) => Ok(value.clone()),
            None => {
                let initial_value = (self.base_value_read_callback)(cell_id);
                match initial_value {
                    Some(value) => Ok(value),
                    None => Err(StateError::StateReadError(format!("{cell_id:?}"))),
                }
            }
        }
    }

    pub fn write(&mut self, cell_id: K, version: Version, value: V) {
        let writes_map = self.writes.entry(cell_id).or_default();
        writes_map.insert(version, value);
    }
}
