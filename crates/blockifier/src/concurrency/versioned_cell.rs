use std::collections::BTreeMap;

#[cfg(test)]
#[path = "versioned_cell_test.rs"]
pub mod test;

pub(crate) type VersionId = u64;

#[derive(Clone)]
pub struct VersionedCell<T> {
    pub initial_value: T,
    pub write_versions: BTreeMap<VersionId, T>,
}

impl<T> VersionedCell<T> {
    pub fn new(initial_value: T) -> Self {
        VersionedCell { initial_value, write_versions: BTreeMap::new() }
    }

    // Retrieving the most recent value written by a version less than or equal to the provided
    // version.
    pub fn read(&self, id: VersionId) -> &T {
        let closest_version =
            self.write_versions.range(..=id).next_back().map(|(&version, _)| version);

        let last_value = closest_version.and_then(|version| self.write_versions.get(&version));
        if let Some(last_value) = last_value { last_value } else { &self.initial_value }
    }

    pub fn write(&mut self, version: VersionId, value: T) {
        self.write_versions.insert(version, value);
    }
}
