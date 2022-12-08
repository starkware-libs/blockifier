use std::mem;

use anyhow::Result;
use starknet_api::hash::StarkFelt;

use crate::execution::syscall_structs::{
    StorageReadRequest, StorageReadResponse, StorageWriteRequest, StorageWriteResponse,
    STORAGE_READ_REQUEST_SIZE, STORAGE_READ_RESPONSE_SIZE, STORAGE_WRITE_REQUEST_SIZE,
    STORAGE_WRITE_RESPONSE_SIZE,
};

pub fn size_in_felts<T>() -> usize {
    mem::size_of::<T>() / mem::size_of::<StarkFelt>()
}

#[test]
fn test_syscall_struct_sizes() -> Result<()> {
    // TODO(AlonH, 21/12/2022): Make sure all structs are tested.
    assert_eq!(size_in_felts::<StorageReadRequest>(), STORAGE_READ_REQUEST_SIZE);
    assert_eq!(size_in_felts::<StorageReadResponse>(), STORAGE_READ_RESPONSE_SIZE);
    assert_eq!(size_in_felts::<StorageWriteRequest>(), STORAGE_WRITE_REQUEST_SIZE);
    assert_eq!(size_in_felts::<StorageWriteResponse>(), STORAGE_WRITE_RESPONSE_SIZE);
    Ok(())
}
