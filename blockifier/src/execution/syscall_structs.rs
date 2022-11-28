use starknet_api::StarkFelt;

// TODO(AlonH, 21/12/2022): Couple Rust's syscall structs with Cairo's.
pub struct StorageReadRequest {
    pub selector: StarkFelt,
    pub address: StarkFelt,
}

pub struct StorageReadResponse {
    pub value: StarkFelt,
}

pub struct StorageRead {
    pub request: StorageReadRequest,
    pub response: StorageReadResponse,
}

pub struct StorageWrite {
    pub selector: StarkFelt,
    pub address: StarkFelt,
    pub value: StarkFelt,
}
