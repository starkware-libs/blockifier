// Calldata.
pub const GAS_PER_MEMORY_ZERO_BYTE: usize = 4;
pub const GAS_PER_MEMORY_BYTE: usize = 16;
pub const WORD_WIDTH: usize = 32;
pub const GAS_PER_MEMORY_WORD: usize = GAS_PER_MEMORY_BYTE * WORD_WIDTH;

// Blob Data.
pub const FIELD_ELEMENTS_PER_BLOB: usize = 1 << 12;
pub const DATA_GAS_PER_BLOB: usize = 1 << 17;
pub const DATA_GAS_PER_FIELD_ELEMENT: usize = DATA_GAS_PER_BLOB / FIELD_ELEMENTS_PER_BLOB;

// Storage.
pub const GAS_PER_ZERO_TO_NONZERO_STORAGE_SET: usize = 20000;
pub const GAS_PER_COLD_STORAGE_ACCESS: usize = 2100;
pub const GAS_PER_NONZERO_TO_INT_STORAGE_SET: usize = 2900;
pub const GAS_PER_COUNTER_DECREASE: usize =
    GAS_PER_COLD_STORAGE_ACCESS + GAS_PER_NONZERO_TO_INT_STORAGE_SET;

// Events.
pub const GAS_PER_LOG: usize = 375;
pub const GAS_PER_LOG_TOPIC: usize = 375;
pub const GAS_PER_LOG_DATA_BYTE: usize = 8;
pub const GAS_PER_LOG_DATA_WORD: usize = GAS_PER_LOG_DATA_BYTE * WORD_WIDTH;

// SHARP empirical costs.
pub const SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD: usize = 100; // This value is not accurate.
pub const SHARP_GAS_PER_MEMORY_WORD: usize =
    GAS_PER_MEMORY_WORD + SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD;
// 10% discount for data availability.
pub const DISCOUNT_PER_DA_WORD: usize = (SHARP_GAS_PER_MEMORY_WORD * 10) / 100;
pub const SHARP_GAS_PER_DA_WORD: usize = SHARP_GAS_PER_MEMORY_WORD - DISCOUNT_PER_DA_WORD;

// TODO(Yoni, 1/1/2025): rename this file to `_utils`.
pub fn get_calldata_word_cost(n_nonzero_bytes: usize) -> usize {
    n_nonzero_bytes * GAS_PER_MEMORY_BYTE
        + (WORD_WIDTH - n_nonzero_bytes) * GAS_PER_MEMORY_ZERO_BYTE
}
