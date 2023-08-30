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

// Gas Cost.
// See documentation in core/os/constants.cairo.
pub const STEP_GAS_COST: u64 = 100;
pub const RANGE_CHECK_GAS_COST: u64 = 70;

// An estimation of the initial gas for a transaction to run with. This solution is temporary and
// this value will become a field of the transaction.
pub const INITIAL_GAS_COST: u64 = 10_u64.pow(8) * STEP_GAS_COST;
// Compiler gas costs.
pub const ENTRY_POINT_INITIAL_BUDGET: u64 = 100 * STEP_GAS_COST;
// OS gas costs.
pub const ENTRY_POINT_GAS_COST: u64 = ENTRY_POINT_INITIAL_BUDGET + 500 * STEP_GAS_COST;
pub const FEE_TRANSFER_GAS_COST: u64 = ENTRY_POINT_GAS_COST + 100 * STEP_GAS_COST;
pub const TRANSACTION_GAS_COST: u64 =
    (2 * ENTRY_POINT_GAS_COST) + FEE_TRANSFER_GAS_COST + (100 * STEP_GAS_COST);
// The required gas for each syscall minus the base amount that was pre-charged (by the compiler).
pub const CALL_CONTRACT_GAS_COST: u64 = 10 * STEP_GAS_COST + ENTRY_POINT_GAS_COST;
pub const DEPLOY_GAS_COST: u64 = 200 * STEP_GAS_COST + ENTRY_POINT_GAS_COST;
pub const EMIT_EVENT_GAS_COST: u64 = 10 * STEP_GAS_COST;
pub const GET_BLOCK_HASH_GAS_COST: u64 = 50 * STEP_GAS_COST;
pub const GET_EXECUTION_INFO_GAS_COST: u64 = 10 * STEP_GAS_COST;
pub const KECCAK_GAS_COST: u64 = 0;
pub const KECCAK_ROUND_COST_GAS_COST: u64 = 180000;
pub const LIBRARY_CALL_GAS_COST: u64 = CALL_CONTRACT_GAS_COST;
pub const REPLACE_CLASS_GAS_COST: u64 = 50 * STEP_GAS_COST;
pub const SECP256K1_ADD_GAS_COST: u64 = 254 * STEP_GAS_COST + 29 * RANGE_CHECK_GAS_COST;
pub const SECP256K1_GET_POINT_FROM_X_GAS_COST: u64 =
    260 * STEP_GAS_COST + 30 * RANGE_CHECK_GAS_COST;
pub const SECP256K1_GET_XY_GAS_COST: u64 = 24 * STEP_GAS_COST + 9 * RANGE_CHECK_GAS_COST;
pub const SECP256K1_MUL_GAS_COST: u64 = 121810 * STEP_GAS_COST + 10739 * RANGE_CHECK_GAS_COST;
pub const SECP256K1_NEW_GAS_COST: u64 = 340 * STEP_GAS_COST + 36 * RANGE_CHECK_GAS_COST;
pub const SECP256R1_ADD_GAS_COST: u64 = 578 * STEP_GAS_COST + 57 * RANGE_CHECK_GAS_COST;
pub const SECP256R1_GET_POINT_FROM_X_GAS_COST: u64 =
    535 * STEP_GAS_COST + 44 * RANGE_CHECK_GAS_COST;
pub const SECP256R1_GET_XY_GAS_COST: u64 = 159 * STEP_GAS_COST + 9 * RANGE_CHECK_GAS_COST;
pub const SECP256R1_MUL_GAS_COST: u64 = 196096 * STEP_GAS_COST + 21477 * RANGE_CHECK_GAS_COST;
pub const SECP256R1_NEW_GAS_COST: u64 = 616 * STEP_GAS_COST + 49 * RANGE_CHECK_GAS_COST;
pub const SEND_MESSAGE_TO_L1_GAS_COST: u64 = 50 * STEP_GAS_COST;
pub const STORAGE_READ_GAS_COST: u64 = 50 * STEP_GAS_COST;
pub const STORAGE_WRITE_GAS_COST: u64 = 50 * STEP_GAS_COST;

// OS reserved contract addresses.

// This contract stores the block number -> block hash mapping.
// TODO(Arni, 14/6/2023): Replace BLOCK_HASH_CONSTANT_ADDRESS with a lazy calculation.
//      pub static BLOCK_HASH_CONTRACT_ADDRESS: Lazy<ContractAddress> = ...
pub const BLOCK_HASH_CONTRACT_ADDRESS: u64 = 1;

// The block number -> block hash mapping is written for the current block number minus this number.
pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
