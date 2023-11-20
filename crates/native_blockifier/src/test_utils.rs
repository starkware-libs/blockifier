use std::collections::HashMap;

use crate::errors::NativeBlockifierResult;
use crate::storage::Storage;

pub struct MockStorage {
    pub block_number_to_class_hash: HashMap<u64, Vec<u8>>,
    // .. Add more as needed.
}
impl Storage for MockStorage {
    fn get_block_id(&self, block_number: u64) -> NativeBlockifierResult<Option<Vec<u8>>> {
        Ok(self.block_number_to_class_hash.get(&block_number).cloned())
    }

    fn get_state_marker(&self) -> NativeBlockifierResult<u64> {
        todo!()
    }

    fn get_header_marker(&self) -> NativeBlockifierResult<u64> {
        todo!()
    }

    fn revert_block(&mut self, _block_number: u64) -> NativeBlockifierResult<()> {
        todo!()
    }

    fn append_block(
        &mut self,
        _block_id: u64,
        _previous_block_id: Option<crate::py_utils::PyFelt>,
        _py_block_info: crate::py_state_diff::PyBlockInfo,
        _py_state_diff: crate::py_state_diff::PyStateDiff,
        _declared_class_hash_to_class: HashMap<
            crate::py_utils::PyFelt,
            (crate::py_utils::PyFelt, String),
        >,
        _deprecated_declared_class_hash_to_class: HashMap<crate::py_utils::PyFelt, String>,
    ) -> NativeBlockifierResult<()> {
        todo!()
    }

    fn validate_aligned(&self, _source_block_number: u64) {
        todo!()
    }

    fn reader(&self) -> &papyrus_storage::StorageReader {
        todo!()
    }

    fn writer(&mut self) -> &mut papyrus_storage::StorageWriter {
        todo!()
    }

    fn close(&mut self) {
        todo!()
    }
}
