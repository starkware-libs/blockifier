use std::collections::BTreeMap;

#[cfg(test)]
#[path = "versioned_cell_test.rs"]
pub mod test;

pub(crate) type Version = u64;

/// A storage cell.
/// It is versioned in the sense that it holds a state of read and writes operation done on it by
/// different versions of executions.
/// This allows maintaining the cell with the correct value in the context of each execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedCell<T> {
    pub initial_value: T,
    pub writes: BTreeMap<Version, T>,
}

impl<T> VersionedCell<T> {
    pub fn new(initial_value: T) -> Self {
        VersionedCell { initial_value, writes: BTreeMap::new() }
    }

    // Retrieves the most recent value written by a version less than or equal to the provided
    // version.
    pub fn read(&self, version: Version) -> &T {
        self.writes.range(..=version).next_back().map_or(&self.initial_value, |(_, value)| value)
    }

    pub fn write(&mut self, version: Version, value: T) {
        self.writes.insert(version, value);
    }
}
