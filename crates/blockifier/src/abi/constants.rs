use starknet_api::hash::StarkFelt;
use starknet_api::transaction::TransactionVersion;

pub const CONSTRUCTOR_ENTRY_POINT_NAME: &str = "constructor";
pub const DEFAULT_ENTRY_POINT_NAME: &str = "__default__";
pub const DEFAULT_ENTRY_POINT_SELECTOR: u64 = 0;
pub const DEFAULT_L1_ENTRY_POINT_NAME: &str = "__l1_default__";

// The version is considered 0 for L1-Handler transaction hash calculation purposes.
pub const L1_HANDLER_VERSION: TransactionVersion = TransactionVersion(StarkFelt::ZERO);

// OS-related constants.
pub const L1_TO_L2_MSG_HEADER_SIZE: usize = 5;
pub const L2_TO_L1_MSG_HEADER_SIZE: usize = 3;
pub const CLASS_UPDATE_SIZE: usize = 1;

// Starknet solidity contract-related constants.
pub const N_DEFAULT_TOPICS: usize = 1; // Events have one default topic.

// Excluding the default topic.
pub const LOG_MSG_TO_L1_N_TOPICS: usize = 2;
pub const CONSUMED_MSG_TO_L2_N_TOPICS: usize = 3;

// The headers include the payload size, so we need to add +1 since arrays are encoded with two
// additional parameters (offset and length) in solidity.
pub const LOG_MSG_TO_L1_ENCODED_DATA_SIZE: usize =
    (L2_TO_L1_MSG_HEADER_SIZE + 1) - LOG_MSG_TO_L1_N_TOPICS;
pub const CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE: usize =
    (L1_TO_L2_MSG_HEADER_SIZE + 1) - CONSUMED_MSG_TO_L2_N_TOPICS;

// Transaction resource names.
pub const MAX_VALIDATE_STEPS_PER_TX: usize = 1_000_000;
pub const MAX_STEPS_PER_TX: usize = 4_000_000;
pub const L1_GAS_USAGE: &str = "l1_gas_usage";
pub const BLOB_GAS_USAGE: &str = "l1_blob_gas_usage";
pub const N_STEPS_RESOURCE: &str = "n_steps";

// Casm hash calculation-related constants.
pub const CAIRO0_ENTRY_POINT_STRUCT_SIZE: usize = 2;
pub const N_STEPS_PER_PEDERSEN: usize = 8;

// OS reserved contract addresses.

// This contract stores the block number -> block hash mapping.
// TODO(Arni, 14/6/2023): Replace BLOCK_HASH_CONSTANT_ADDRESS with a lazy calculation.
//      pub static BLOCK_HASH_CONTRACT_ADDRESS: Lazy<ContractAddress> = ...
pub const BLOCK_HASH_CONTRACT_ADDRESS: u64 = 1;

// The block number -> block hash mapping is written for the current block number minus this number.
pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
