use assert_matches::assert_matches;
use cairo_native::utils::get_integer_layout;
use starknet_api::core::ClassHash;

use crate::execution::contract_class::ContractClass;
use crate::state::state_api::State;
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

fn assert_contract_uses_native(class_hash: ClassHash, state: &dyn State) {
    assert_matches!(
        state
            .get_compiled_contract_class(class_hash)
            .unwrap_or_else(|_| panic!("Expected contract class at {class_hash}")),
        ContractClass::V1Sierra(_)
    )
}

fn assert_contract_uses_vm(class_hash: ClassHash, state: &dyn State) {
    assert_matches!(
        state
            .get_compiled_contract_class(class_hash)
            .unwrap_or_else(|_| panic!("Expected contract class at {class_hash}")),
        ContractClass::V1(_) | ContractClass::V0(_)
    )
}

fn assert_consistent_contract_version(contract: FeatureContract, state: &dyn State) {
    let hash = contract.get_class_hash();
    match contract {
        FeatureContract::SierraTestContract => assert_contract_uses_native(hash, state),
        FeatureContract::SecurityTests
        | FeatureContract::ERC20
        | FeatureContract::LegacyTestContract
        | FeatureContract::AccountWithLongValidate(_)
        | FeatureContract::AccountWithoutValidations(_)
        | FeatureContract::Empty(_)
        | FeatureContract::FaultyAccount(_)
        | FeatureContract::TestContract(_) => assert_contract_uses_vm(hash, state),
    }
}

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

// REBASE NOTE: only run on x86_64
#[test]
fn alignment_test() {
    assert!(get_integer_layout(248).align() <= 8);
    assert!(get_integer_layout(252).align() <= 8);
    assert!(get_integer_layout(256).align() <= 8);
    assert!(get_integer_layout(0).align() <= 8);
    assert!(get_integer_layout(8).align() <= 8);
    assert!(get_integer_layout(16).align() <= 8);
    assert!(get_integer_layout(32).align() <= 8);
    assert!(get_integer_layout(64).align() <= 8);
    assert!(get_integer_layout(128).align() <= 8);
    assert!(get_integer_layout(129).align() <= 8);
}
