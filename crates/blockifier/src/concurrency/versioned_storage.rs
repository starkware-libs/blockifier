use std::collections::{BTreeMap, HashMap};

use crate::state::errors::StateError;
use crate::state::state_api::StateResult;

pub(crate) type Version = u64;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

type ReadCallback<K, V> = dyn Fn(K) -> Option<V>;

pub struct VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Display,
    V: Clone + std::fmt::Debug,
{
    pub base_value_read_callback: Box<ReadCallback<K, V>>,
    pub writes: HashMap<K, BTreeMap<Version, V>>,
}

impl<K, V> VersionedStorage<K, V>
where
    K: Clone + Copy + Eq + std::hash::Hash + std::fmt::Display,
    V: Clone + std::fmt::Debug,
{
    pub fn new(base_value_read_callback: Box<ReadCallback<K, V>>) -> Self {
        VersionedStorage { base_value_read_callback, writes: HashMap::new() }
    }

    pub fn read(&mut self, cell_id: K, version: Version) -> StateResult<&V> {
        match self.writes.entry(cell_id).or_default().range(..=version).next_back() {
            Some((_, _value)) => Ok(_value),
            None => {
                let initial_value = (self.base_value_read_callback)(cell_id);
                match initial_value {
                    Some(value) => Ok(Box::leak(Box::new(value))),
                    None => Err(StateError::StateReadError(cell_id.to_string())),
                }
            }
        }
    }

    pub fn write(&mut self, cell_id: K, version: Version, value: V) {
        let writes_map = self.writes.entry(cell_id).or_default();
        writes_map.insert(version, value);
    }
}
