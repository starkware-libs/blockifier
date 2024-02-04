use std::collections::HashMap;

use super::versioned_cell::{VersionId, VersionedCell};

pub(crate) type CellId = u64;

#[cfg(test)]
#[path = "versioned_storage_test.rs"]
pub mod test;

type ReadCallback<CellId, V> = dyn Fn(CellId) -> Option<V>;

pub struct VersionedStorage<V> {
    pub base_value_read_callback: Box<ReadCallback<CellId, V>>,
    pub versioned_cells: HashMap<CellId, VersionedCell<V>>,
}

impl<V> VersionedStorage<V> {
    pub fn new(base_value_read_callback: Box<ReadCallback<CellId, V>>) -> Self {
        VersionedStorage { base_value_read_callback, versioned_cells: HashMap::new() }
    }

    pub fn read(&mut self, cell_id: CellId, version: VersionId) -> &V {
        let cell = self._get_cell(cell_id);
        cell.read(version)
    }

    pub fn write(&mut self, cell_id: CellId, version: VersionId, value: V) {
        let cell = self._get_cell(cell_id);
        cell.write(version, value);
    }

    pub fn _get_cell(&mut self, cell_id: CellId) -> &mut VersionedCell<V> {
        self.versioned_cells.entry(cell_id).or_insert_with(|| {
            let base_value = (self.base_value_read_callback)(cell_id).unwrap();
            VersionedCell::new(base_value)
        })
    }
}
