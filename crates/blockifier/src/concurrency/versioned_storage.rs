use std::collections::{BTreeMap, HashMap};

use crate::state::state_api::StateResult;

pub(crate) type Version = u64;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

type ReadCallback<K, V> = dyn Fn(K) -> StateResult<V>;

pub struct VersionedStorage<K, V>
where
    K: Clone + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub base_value_read_callback: Box<ReadCallback<K, V>>,
    pub writes: HashMap<K, BTreeMap<Version, V>>,
}

impl<K, V> VersionedStorage<K, V>
where
    K: Clone + Eq + std::hash::Hash + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    pub fn new(base_value_read_callback: Box<ReadCallback<K, V>>) -> Self {
        VersionedStorage { base_value_read_callback, writes: HashMap::new() }
    }

    pub fn read(&mut self, cell_id: K, version: Version) -> V {
        dbg!("version: ", version);
        match self.writes.entry(cell_id.clone()).or_default().range(..=version).next_back() {
            Some((_, value)) => value.clone(),
            None => {
                let base_value = (self.base_value_read_callback)(cell_id);
                base_value.expect("Base value read callback returned an error")
            }
        }
    }

    pub fn write(&mut self, cell_id: K, version: Version, value: V) {
        let writes_map = self.writes.entry(cell_id).or_default();
        writes_map.insert(version, value);
    }
}
