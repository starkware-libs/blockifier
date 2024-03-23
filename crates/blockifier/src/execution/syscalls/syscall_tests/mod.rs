mod call_contract;
mod deploy;
mod emit_event;
mod get_block_hash;
mod get_execution_info;
mod keccak;
mod library_call;
mod replace_class;
mod secp;
mod send_message_to_l1;
mod storage_read_write;

use std::panic;

use assert_matches::assert_matches;
use cairo_lang_utils::byte_array::BYTE_ARRAY_MAGIC;
use pretty_assertions::assert_eq;
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::syscalls::hint_processor::OUT_OF_GAS_ERROR;
use crate::state::state_api::State;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{trivial_external_entry_point_new, CairoVersion, BALANCE};

pub const REQUIRED_GAS_STORAGE_READ_WRITE_TEST: u64 = 34650;
pub const REQUIRED_GAS_CALL_CONTRACT_TEST: u64 = 128080;
pub const REQUIRED_GAS_LIBRARY_CALL_TEST: u64 = REQUIRED_GAS_CALL_CONTRACT_TEST;

fn assert_contract_uses_native(class_hash: ClassHash, state: &dyn State) {
    assert_matches!(
        state
            .get_compiled_contract_class(class_hash)
            .expect(&format!("Expected contract class at {class_hash}")),
        ContractClass::V1Sierra(_)
    )
}

fn assert_contract_uses_vm(class_hash: ClassHash, state: &dyn State) {
    assert_matches!(
        state
            .get_compiled_contract_class(class_hash)
            .expect(&format!("Expected contract class at {class_hash}")),
        ContractClass::V1(_) | ContractClass::V0(_)
    )
}

fn assert_consistent_contract_version(contract: FeatureContract, state: &dyn State) {
    let hash = contract.get_class_hash();
    match contract {
        FeatureContract::SecurityTests | FeatureContract::ERC20 => {
            assert_contract_uses_vm(hash, state)
        }
        FeatureContract::LegacyTestContract | FeatureContract::SierraTestContract => {
            assert_contract_uses_native(hash, state)
        }
        FeatureContract::AccountWithLongValidate(_)
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

#[test_case(FeatureContract::SierraTestContract; "Native")] // fail bc it doesn't limit on gas, not expecting it to yet
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")] // pass
fn test_out_of_gas(test_contract: FeatureContract) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        initial_gas: REQUIRED_GAS_STORAGE_READ_WRITE_TEST - 1,
        ..trivial_external_entry_point_new(test_contract)
    };
    let error = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert_matches!(error, EntryPointExecutionError::ExecutionFailed{ error_data }
        if error_data == vec![stark_felt!(OUT_OF_GAS_ERROR)]);
}

#[test] // pass
fn test_syscall_failure_format() {
    let error_data = vec![
        // Magic to indicate that this is a byte array.
        BYTE_ARRAY_MAGIC,
        // the number of full words in the byte array.
        "0x00",
        // The pending word of the byte array: "Execution failure"
        "0x457865637574696f6e206661696c757265",
        // The length of the pending word.
        "0x11",
    ]
    .into_iter()
    .map(|x| StarkFelt::try_from(x).unwrap())
    .collect();
    let error = EntryPointExecutionError::ExecutionFailed { error_data };
    assert_eq!(error.to_string(), "Execution failed. Failure reason: \"Execution failure\".");
}
