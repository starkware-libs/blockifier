use crate::test_utils::contracts::FeatureContract;

mod call_contract;
mod deploy;
mod emit_event;
mod get_block_hash;
mod get_execution_info;
mod keccak;
mod library_call;
mod out_of_gas;
mod replace_class;
mod secp;
mod send_message_to_l1;
mod storage_read_write;

pub const REQUIRED_GAS_CALL_CONTRACT_TEST: u64 = 105680;
pub const REQUIRED_GAS_STORAGE_READ_WRITE_TEST: u64 = 27150;
pub const REQUIRED_GAS_LIBRARY_CALL_TEST: u64 = REQUIRED_GAS_CALL_CONTRACT_TEST;

fn verify_compiler_version(contract: FeatureContract, expected_version: &str) {
    // Read and parse file content.
    let raw_contract: serde_json::Value =
        serde_json::from_str(&contract.get_raw_class()).expect("Error parsing JSON");

    // Verify version.
    if let Some(compiler_version) = raw_contract["compiler_version"].as_str() {
        assert_eq!(compiler_version, expected_version);
    } else {
        panic!("'compiler_version' not found or not a valid string in JSON.");
    }
}
