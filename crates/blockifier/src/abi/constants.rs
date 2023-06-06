pub const CONSTRUCTOR_ENTRY_POINT_NAME: &str = "constructor";
pub const DEFAULT_ENTRY_POINT_NAME: &str = "__default__";
pub const DEFAULT_ENTRY_POINT_SELECTOR: u64 = 0;
pub const DEFAULT_L1_ENTRY_POINT_NAME: &str = "__l1_default__";

// The version is considered 0 for L1-Handler transaction hash calculation purposes.
pub const L1_HANDLER_VERSION: u64 = 0;

// OS-related constants.
pub const L1_TO_L2_MSG_HEADER_SIZE: usize = 5;
pub const L2_TO_L1_MSG_HEADER_SIZE: usize = 3;
pub const CLASS_UPDATE_SIZE: usize = 1;

// StarkNet solidity contract-related constants.
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
pub const MAX_STEPS_PER_TX: usize = 4_000_000;
pub const GAS_USAGE: &str = "l1_gas_usage";
pub const N_STEPS_RESOURCE: &str = "n_steps";

// Casm hash calculation-related constants.
pub const CAIRO0_ENTRY_POINT_STRUCT_SIZE: usize = 2;
pub const N_STEPS_PER_PEDERSEN: usize = 8;
