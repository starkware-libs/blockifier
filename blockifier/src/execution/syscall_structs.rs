use num_bigint::BigInt;

// TODO(AlonH, 21/12/2022): Couple Rust's syscall structs with Cairo's.
pub struct StorageReadRequest {
    // TODO(AlonH, 21/12/2022): Change to StarkFelt.
    pub selector: BigInt,
    pub address: BigInt,
}

pub struct StorageReadResponse {
    // TODO(AlonH, 21/12/2022): Change to StarkFelt.
    pub value: BigInt,
}

pub struct StorageRead {
    pub request: StorageReadRequest,
    pub response: StorageReadResponse,
}
