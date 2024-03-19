use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic;

use assert_matches::assert_matches;
use cairo_felt::Felt252;
use cairo_lang_utils::byte_array::BYTE_ARRAY_MAGIC;
use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::concat;
use num_traits::Pow;
use pretty_assertions::assert_eq;
use starknet_api::core::{
    calculate_contract_address, ChainId, ClassHash, ContractAddress, EthAddress, Nonce, PatriciaKey,
};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, ContractAddressSalt, EventContent, EventData, EventKey, Fee,
    L2ToL1Payload, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping, Tip,
    TransactionHash, TransactionVersion,
};
use starknet_api::{calldata, class_hash, contract_address, patricia_key, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants;
use crate::context::ChainInfo;
use crate::execution::call_info::{
    CallExecution, CallInfo, MessageToL1, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::common_hints::ExecutionMode;
use crate::execution::contract_class::{ContractClass, ContractClassV0};
use crate::execution::entry_point::{CallEntryPoint, CallType};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::execution::sierra_utils::NATIVE_GAS_PLACEHOLDER;
use crate::execution::syscalls::hint_processor::{
    EmitEventError, BLOCK_NUMBER_OUT_OF_RANGE_ERROR, FAILED_TO_EXECUTE_CALL,
    INVALID_EXECUTION_MODE_ERROR, L1_GAS, L2_GAS, OUT_OF_GAS_ERROR,
};
use crate::retdata;
use crate::state::state_api::{State, StateReader};
use crate::test_utils::cached_state::create_deploy_test_state;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    create_calldata, trivial_external_entry_point, trivial_external_entry_point_new, CairoVersion,
    BALANCE, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_NUMBER_FOR_VALIDATE,
    CURRENT_BLOCK_TIMESTAMP, CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_EMPTY_CONTRACT_CAIRO0_PATH, TEST_EMPTY_CONTRACT_CLASS_HASH,
    TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    CommonAccountFields, CurrentTransactionInfo, DeprecatedTransactionInfo, TransactionInfo,
};
use crate::versioned_constants::VersionedConstants;

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

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // pass
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), REQUIRED_GAS_STORAGE_READ_WRITE_TEST; "VM")] // pass
fn test_storage_read_write(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    assert_consistent_contract_version(test_contract, &state);

    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(value)],
            gas_consumed: expected_gas,
            ..CallExecution::default()
        }
    );

    // Verify that the state has changed.
    let value_from_state =
        state.get_storage_at(storage_address, StorageKey::try_from(key).unwrap()).unwrap();
    assert_eq!(value_from_state, value);

    // ensure that the fallback system didn't replace the contract
    assert_consistent_contract_version(test_contract, &state);
}

#[test_case(
    FeatureContract::SierraTestContract,
    FeatureContract::SierraTestContract,
    NATIVE_GAS_PLACEHOLDER;
    "Call Contract between two contracts using Native")] // pass
#[test_case(
    FeatureContract::SierraTestContract,
    FeatureContract::TestContract(CairoVersion::Cairo1),
    NATIVE_GAS_PLACEHOLDER;
    "Call Contract with caller using Native and callee using VM")] // pass
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    FeatureContract::SierraTestContract,
    93430 + NATIVE_GAS_PLACEHOLDER;
    "Call Contract with caller using VM and callee using Native")] // pass
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    FeatureContract::TestContract(CairoVersion::Cairo1),
    REQUIRED_GAS_CALL_CONTRACT_TEST;
    "Call Contract between two contracts using VM")] // pass
fn test_call_contract(
    outer_contract: FeatureContract,
    inner_contract: FeatureContract,
    expected_gas: u64,
) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(outer_contract, 1), (inner_contract, 1)]);

    assert_consistent_contract_version(outer_contract, &state);
    assert_consistent_contract_version(inner_contract, &state);

    let outer_entry_point_selector = selector_from_name("test_call_contract");
    let calldata = create_calldata(
        inner_contract.get_instance_address(0),
        "test_storage_read_write",
        &[
            stark_felt!(405_u16), // Calldata: address.
            stark_felt!(48_u8),   // Calldata: value.
        ],
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata,
        ..trivial_external_entry_point_new(outer_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(48_u8)],
            gas_consumed: expected_gas,
            ..CallExecution::default()
        }
    );

    // ensure that the fallback system didn't replace the contract
    assert_consistent_contract_version(outer_contract, &state);
    assert_consistent_contract_version(inner_contract, &state);
}

#[cfg(test)]
mod test_emit_event {
    use self::test_case;
    use super::{assert_eq, *};

    const KEYS: [StarkFelt; 2] = [StarkFelt::from_u128(2019), StarkFelt::from_u128(2020)];
    const DATA: [StarkFelt; 3] =
        [StarkFelt::from_u128(2021), StarkFelt::from_u128(2022), StarkFelt::from_u128(2023)];
    const N_EMITTED_EVENTS: [StarkFelt; 1] = [StarkFelt::from_u128(1)];

    #[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")]
    #[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 82930; "VM")]
    fn positive_flow(test_contract: FeatureContract, expected_gas: u64) {
        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
        let call_info = emit_events(test_contract, &N_EMITTED_EVENTS, &KEYS, &DATA).unwrap();
        let event = EventContent {
            keys: KEYS.clone().into_iter().map(EventKey).collect(),
            data: EventData(DATA.to_vec()),
        };
        assert_eq!(
            call_info.execution,
            CallExecution {
                events: vec![OrderedEvent { order: 0, event }],
                gas_consumed: expected_gas,
                ..Default::default()
            }
        );
    }

    #[test_case(FeatureContract::SierraTestContract; "Native")]
    #[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
    fn data_length_exceeds_limit(test_contract: FeatureContract) {
        let versioned_constants = VersionedConstants::create_for_testing();

        let max_event_data_length = versioned_constants.tx_event_limits.max_data_length;
        let data_too_long = vec![stark_felt!(2_u16); max_event_data_length + 1];
        let error =
            emit_events(test_contract, &N_EMITTED_EVENTS, &KEYS, &data_too_long).unwrap_err();
        let expected_error = EmitEventError::ExceedsMaxDataLength {
            data_length: max_event_data_length + 1,
            max_data_length: max_event_data_length,
        };
        assert!(error.to_string().contains(&expected_error.to_string()));
    }

    #[test_case(FeatureContract::SierraTestContract; "Native")]
    #[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
    fn keys_length_exceeds_limit(test_contract: FeatureContract) {
        let versioned_constants = VersionedConstants::create_for_testing();

        let max_event_keys_length = versioned_constants.tx_event_limits.max_keys_length;
        let keys_too_long = vec![stark_felt!(1_u16); max_event_keys_length + 1];
        let error =
            emit_events(test_contract, &N_EMITTED_EVENTS, &keys_too_long, &DATA).unwrap_err();
        let expected_error = EmitEventError::ExceedsMaxKeysLength {
            keys_length: max_event_keys_length + 1,
            max_keys_length: max_event_keys_length,
        };

        assert!(error.to_string().contains(&expected_error.to_string()));
    }

    #[test_case(FeatureContract::SierraTestContract; "Native")]
    #[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
    fn event_number_exceeds_limit(test_contract: FeatureContract) {
        let versioned_constants = VersionedConstants::create_for_testing();

        let max_n_emitted_events = versioned_constants.tx_event_limits.max_n_emitted_events;
        let n_emitted_events_too_big = vec![stark_felt!(
            u16::try_from(max_n_emitted_events + 1).expect("Failed to convert usize to u16.")
        )];
        let error =
            emit_events(test_contract, &n_emitted_events_too_big, &KEYS, &DATA).unwrap_err();
        let expected_error = EmitEventError::ExceedsMaxNumberOfEmittedEvents {
            n_emitted_events: max_n_emitted_events + 1,
            max_n_emitted_events,
        };
        assert!(error.to_string().contains(&expected_error.to_string()));
    }

    fn emit_events(
        test_contract: FeatureContract,
        n_emitted_events: &[StarkFelt],
        keys: &[StarkFelt],
        data: &[StarkFelt],
    ) -> Result<CallInfo, EntryPointExecutionError> {
        let chain_info = &ChainInfo::create_for_testing();
        let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
        assert_consistent_contract_version(test_contract, &state);
        let calldata = Calldata(
            concat(vec![
                n_emitted_events.to_owned(),
                vec![stark_felt!(
                    u16::try_from(keys.len()).expect("Failed to convert usize to u16.")
                )],
                keys.to_vec(),
                vec![stark_felt!(
                    u16::try_from(data.len()).expect("Failed to convert usize to u16.")
                )],
                data.to_vec(),
            ])
            .into(),
        );

        let entry_point_call = CallEntryPoint {
            entry_point_selector: selector_from_name("test_emit_events"),
            calldata,
            ..trivial_external_entry_point_new(test_contract)
        };

        let result = entry_point_call.execute_directly(&mut state);
        assert_consistent_contract_version(test_contract, &state);
        result
    }
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // pass
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 14250; "VM")] // unauthorised syscall get_block_hash in execution mode Validate
fn test_get_block_hash(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
    assert_consistent_contract_version(test_contract, &state);

    // Initialize block number -> block hash entry.
    let upper_bound_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER;
    let block_number = stark_felt!(upper_bound_block_number);
    let block_hash = stark_felt!(66_u64);
    let key = StorageKey::try_from(block_number).unwrap();
    let block_hash_contract_address =
        ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS)).unwrap();
    state.set_storage_at(block_hash_contract_address, key, block_hash).unwrap();

    // Positive flow.
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.clone().execute_directly(&mut state).unwrap().execution,
        CallExecution {
            gas_consumed: expected_gas,
            ..CallExecution::from_retdata(retdata![block_hash])
        }
    );

    assert_consistent_contract_version(test_contract, &state);

    // Negative flow. Execution mode is Validate.
    let execution_result = entry_point_call.execute_directly_in_validate_mode(&mut state).unwrap();

    assert_consistent_contract_version(test_contract, &state);

    assert_matches!(
        execution_result,
        CallInfo { execution: CallExecution { failed: true, .. }, .. }
    );

    let expected_return_data = Retdata(vec![stark_felt!(INVALID_EXECUTION_MODE_ERROR)]);
    assert_eq!(execution_result.execution.retdata, expected_return_data);

    // Negative flow: Block number out of range.
    let requested_block_number = CURRENT_BLOCK_NUMBER - constants::STORED_BLOCK_HASH_BUFFER + 1;
    let block_number = stark_felt!(requested_block_number);
    let calldata = calldata![block_number];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_get_block_hash"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };
    let execution_result = entry_point_call.execute_directly(&mut state).unwrap();

    assert_consistent_contract_version(test_contract, &state);

    assert_matches!(
        execution_result,
        CallInfo { execution: CallExecution { failed: true, .. }, .. }
    );

    let expected_return_data = Retdata(vec![stark_felt!(BLOCK_NUMBER_OUT_OF_RANGE_ERROR)]);

    assert_eq!(execution_result.execution.retdata, expected_return_data);
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 354940; "VM")]
fn test_keccak(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_keccak"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: expected_gas, ..CallExecution::from_retdata(retdata![]) }
    );
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

#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Validate,
    TransactionVersion::ONE,
    false;
    "Native. Validate execution mode: block info fields should be zeroed. Transaction V1.")] // transaction fails
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Native. Execute execution mode: block info fields should be zeroed. Transaction V1.")] // transaction fails
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Validate,
    TransactionVersion::THREE,
    false;
    "Native. Validate execution mode: block info fields should be zeroed. Transaction V3.")] // transaction fails
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Native. Execute execution mode: block info fields should be zeroed. Transaction V3.")] // transaction fails
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    true;
    "Native. Execute execution mode: block info should be as usual. Transaction V3. Query.")] // transaction fails
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Validate,
    TransactionVersion::ONE,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V1.")] // pass
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Execute execution mode: block info fields should be zeroed. Transaction V1.")] // pass
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Validate,
    TransactionVersion::THREE,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V3.")] // pass
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Execute execution mode: block info fields should be zeroed. Transaction V3.")] // pass
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    true;
    "Execute execution mode: block info should be as usual. Transaction V3. Query.")] // pass
#[test_case(
    FeatureContract::LegacyTestContract,
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V1.")] // pass
#[test_case(
    FeatureContract::LegacyTestContract,
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V3.")] // pass
fn test_get_execution_info(
    test_contract: FeatureContract,
    execution_mode: ExecutionMode,
    mut version: TransactionVersion,
    only_query: bool,
) {
    let state = &mut test_state(&ChainInfo::create_for_testing(), BALANCE, &[(test_contract, 1)]);

    let expected_block_info = match execution_mode {
        ExecutionMode::Validate => [
            // Rounded block number.
            stark_felt!(CURRENT_BLOCK_NUMBER_FOR_VALIDATE),
            // Rounded timestamp.
            stark_felt!(CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE),
            StarkFelt::ZERO,
        ],
        ExecutionMode::Execute => [
            stark_felt!(CURRENT_BLOCK_NUMBER),    // Block number.
            stark_felt!(CURRENT_BLOCK_TIMESTAMP), // Block timestamp.
            StarkFelt::try_from(TEST_SEQUENCER_ADDRESS).unwrap(),
        ],
    };

    let (test_contract_address, expected_unsupported_fields) = match test_contract {
        FeatureContract::LegacyTestContract => {
            verify_compiler_version(test_contract, "2.1.0");
            (test_contract.get_instance_address(0), vec![])
        }
        FeatureContract::SierraTestContract
        | FeatureContract::TestContract(CairoVersion::Cairo1) => {
            (
                test_contract.get_instance_address(0),
                vec![
                    StarkFelt::ZERO, // Tip.
                    StarkFelt::ZERO, // Paymaster data.
                    StarkFelt::ZERO, // Nonce DA.
                    StarkFelt::ZERO, // Fee DA.
                    StarkFelt::ZERO, // Account data.
                ],
            )
        }
        _ => panic!("unexpected feature contract"),
    };

    if only_query {
        let simulate_version_base = Pow::pow(Felt252::from(2_u8), QUERY_VERSION_BASE_BIT);
        let query_version = simulate_version_base + stark_felt_to_felt(version.0);
        version = TransactionVersion(felt_to_stark_felt(&query_version));
    }

    let tx_hash = TransactionHash(stark_felt!(1991_u16));
    let max_fee = Fee(42);
    let nonce = Nonce(stark_felt!(3_u16));
    let sender_address = test_contract_address;

    let expected_tx_info: Vec<StarkFelt>;
    let mut expected_resource_bounds: Vec<StarkFelt> = vec![];
    let tx_info: TransactionInfo;
    if version == TransactionVersion::ONE {
        expected_tx_info = vec![
            version.0,                                                  // Transaction version.
            *sender_address.0.key(),                                    // Account address.
            stark_felt!(max_fee.0),                                     // Max fee.
            StarkFelt::ZERO,                                            // Signature.
            tx_hash.0,                                                  // Transaction hash.
            stark_felt!(&*ChainId(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
            nonce.0,                                                    // Nonce.
        ];
        if !matches!(test_contract, FeatureContract::LegacyTestContract) {
            expected_resource_bounds = vec![
                stark_felt!(0_u16), // Length of resource bounds array.
            ];
        }
        tx_info = TransactionInfo::Deprecated(DeprecatedTransactionInfo {
            common_fields: CommonAccountFields {
                transaction_hash: tx_hash,
                version: TransactionVersion::ONE,
                nonce,
                sender_address,
                only_query,
                ..Default::default()
            },
            max_fee,
        });
    } else {
        let max_amount = Fee(13);
        let max_price_per_unit = Fee(61);
        expected_tx_info = vec![
            version.0,                                                  // Transaction version.
            *sender_address.0.key(),                                    // Account address.
            StarkFelt::ZERO,                                            // Max fee.
            StarkFelt::ZERO,                                            // Signature.
            tx_hash.0,                                                  // Transaction hash.
            stark_felt!(&*ChainId(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
            nonce.0,                                                    // Nonce.
        ];
        if !matches!(test_contract, FeatureContract::LegacyTestContract) {
            expected_resource_bounds = vec![
                StarkFelt::from(2u32),             // Length of ResourceBounds array.
                stark_felt!(L1_GAS),               // Resource.
                stark_felt!(max_amount.0),         // Max amount.
                stark_felt!(max_price_per_unit.0), // Max price per unit.
                stark_felt!(L2_GAS),               // Resource.
                StarkFelt::ZERO,                   // Max amount.
                StarkFelt::ZERO,                   // Max price per unit.
            ];
        }
        tx_info = TransactionInfo::Current(CurrentTransactionInfo {
            common_fields: CommonAccountFields {
                transaction_hash: tx_hash,
                version: TransactionVersion::THREE,
                nonce,
                sender_address,
                only_query,
                ..Default::default()
            },
            resource_bounds: ResourceBoundsMapping(BTreeMap::from([
                (
                    Resource::L1Gas,
                    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the
                    // convertion works.
                    ResourceBounds {
                        max_amount: max_amount
                            .0
                            .try_into()
                            .expect("Failed to convert u128 to u64."),
                        max_price_per_unit: max_price_per_unit.0,
                    },
                ),
                (Resource::L2Gas, ResourceBounds { max_amount: 0, max_price_per_unit: 0 }),
            ])),
            tip: Tip::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: PaymasterData::default(),
            account_deployment_data: AccountDeploymentData::default(),
        });
    }

    let entry_point_selector = selector_from_name("test_get_execution_info");
    let expected_call_info = vec![
        stark_felt!(0_u16),                  // Caller address.
        *test_contract_address.0.key(),      // Storage address.
        stark_felt!(entry_point_selector.0), // Entry point selector.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        storage_address: test_contract_address,
        calldata: Calldata(
            [
                expected_block_info.to_vec(),
                expected_tx_info,
                expected_resource_bounds,
                expected_unsupported_fields,
                expected_call_info,
            ]
            .concat()
            .into(),
        ),
        ..trivial_external_entry_point()
    };
    let result = match execution_mode {
        ExecutionMode::Validate => {
            entry_point_call.execute_directly_given_tx_info_in_validate_mode(state, tx_info, false)
        }
        ExecutionMode::Execute => {
            entry_point_call.execute_directly_given_tx_info(state, tx_info, false)
        }
    };

    assert!(!result.unwrap().execution.failed);
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), REQUIRED_GAS_LIBRARY_CALL_TEST; "VM")]
fn test_library_call(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let calldata = calldata![
        test_contract.get_class_hash().0, // Class hash.
        inner_entry_point_selector.0,     // Function selector.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(1234_u16),            // Calldata: address.
        stark_felt!(91_u8)                // Calldata: value.
    ];

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(test_contract.get_class_hash()),
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(91_u16)],
            gas_consumed: expected_gas,
            ..Default::default()
        }
    );
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn test_library_call_assert_fails(test_contract: FeatureContract) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
    let inner_entry_point_selector = selector_from_name("assert_eq");
    let calldata = calldata![
        test_contract.get_class_hash().0, // Class hash.
        inner_entry_point_selector.0,     // Function selector.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(0_u8),                // Calldata: first assert value.
        stark_felt!(1_u8)                 // Calldata: second assert value.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_library_call"),
        calldata,
        class_hash: Some(test_contract.get_class_hash()),
        ..trivial_external_entry_point_new(test_contract)
    };

    let err = entry_point_call.execute_directly(&mut state).unwrap_err();
    assert!(err.to_string().contains("x != y"));
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 316180; "VM")]
fn test_nested_library_call(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let (key, value) = (255_u64, 44_u64);
    let outer_entry_point_selector = selector_from_name("test_library_call");
    let inner_entry_point_selector = selector_from_name("test_storage_read_write");
    let test_class_hash = test_contract.get_class_hash();
    let main_entry_point_calldata = calldata![
        test_class_hash.0,            // Class hash.
        outer_entry_point_selector.0, // Library call function selector.
        inner_entry_point_selector.0, // Storage function selector.
        stark_felt!(key),             // Calldata: address.
        stark_felt!(value)            // Calldata: value.
    ];

    // Todo(rodrigo): Execution resources from the VM & Native are mesaured differently
    // helper function to change the expected resource values from both of executions
    let if_sierra = |a, b| {
        if matches!(test_contract, FeatureContract::SierraTestContract) {
            a
        } else {
            b
        }
    };

    // Create expected call info tree.
    let main_entry_point = CallEntryPoint {
        entry_point_selector: selector_from_name("test_nested_library_call"),
        calldata: main_entry_point_calldata,
        class_hash: Some(test_class_hash),
        initial_gas: 9999906600,
        ..trivial_external_entry_point_new(test_contract)
    };
    let nested_storage_entry_point = CallEntryPoint {
        entry_point_selector: inner_entry_point_selector,
        calldata: calldata![stark_felt!(key + 1), stark_felt!(value + 1)],
        class_hash: Some(test_class_hash),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: if_sierra(9999827120, 9999720720),
        ..trivial_external_entry_point_new(test_contract)
    };
    let library_entry_point = CallEntryPoint {
        entry_point_selector: outer_entry_point_selector,
        calldata: calldata![
            test_class_hash.0,            // Class hash.
            inner_entry_point_selector.0, // Storage function selector.
            stark_felt!(2_u8),            // Calldata: address.
            stark_felt!(key + 1),         // Calldata: address.
            stark_felt!(value + 1)        // Calldata: value.
        ],
        class_hash: Some(test_class_hash),
        code_address: None,
        call_type: CallType::Delegate,
        initial_gas: if_sierra(9999865550, 9999814150),
        ..trivial_external_entry_point_new(test_contract)
    };
    let storage_entry_point = CallEntryPoint {
        calldata: calldata![stark_felt!(key), stark_felt!(value)],
        initial_gas: if_sierra(9999865550, 9999625070),
        ..nested_storage_entry_point
    };

    // Todo(rodrigo): Execution resources from the VM & Native are mesaured differently
    // Resources are not tracked when using Native
    let default_resources_if_sierra = |resources| {
        if matches!(test_contract, FeatureContract::SierraTestContract) {
            ExecutionResources::default()
        } else {
            resources
        }
    };

    let storage_entry_point_resources = default_resources_if_sierra(ExecutionResources {
        n_steps: 319,
        n_memory_holes: 1,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 7)]),
    });
    let nested_storage_call_info = CallInfo {
        call: nested_storage_entry_point,
        execution: CallExecution {
            retdata: retdata![stark_felt!(value + 1)],
            gas_consumed: if_sierra(NATIVE_GAS_PLACEHOLDER, REQUIRED_GAS_STORAGE_READ_WRITE_TEST),
            ..CallExecution::default()
        },
        resources: storage_entry_point_resources.clone(),
        storage_read_values: vec![stark_felt!(value + 1)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key + 1))]),
        ..Default::default()
    };

    let library_call_resources = default_resources_if_sierra(ExecutionResources {
        n_steps: 1338,
        n_memory_holes: 2,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 35)]),
    });
    let library_call_info = CallInfo {
        call: library_entry_point,
        execution: CallExecution {
            retdata: retdata![stark_felt!(value + 1)],
            gas_consumed: if_sierra(NATIVE_GAS_PLACEHOLDER, REQUIRED_GAS_LIBRARY_CALL_TEST),
            ..CallExecution::default()
        },
        resources: library_call_resources,
        inner_calls: vec![nested_storage_call_info],
        ..Default::default()
    };

    let storage_call_info = CallInfo {
        call: storage_entry_point,
        execution: CallExecution {
            retdata: retdata![stark_felt!(value)],
            gas_consumed: if_sierra(NATIVE_GAS_PLACEHOLDER, REQUIRED_GAS_STORAGE_READ_WRITE_TEST),
            ..CallExecution::default()
        },
        resources: storage_entry_point_resources,
        storage_read_values: vec![stark_felt!(value)],
        accessed_storage_keys: HashSet::from([StorageKey(patricia_key!(key))]),
        ..Default::default()
    };

    let main_call_resources = default_resources_if_sierra(ExecutionResources {
        n_steps: 3370,
        n_memory_holes: 4,
        builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 87)]),
    });
    let expected_call_info = CallInfo {
        call: main_entry_point.clone(),
        execution: CallExecution {
            retdata: retdata![stark_felt!(value)],
            gas_consumed: expected_gas,
            ..CallExecution::default()
        },
        resources: main_call_resources,
        inner_calls: vec![library_call_info, storage_call_info],
        ..Default::default()
    };

    assert_eq!(main_entry_point.execute_directly(&mut state).unwrap(), expected_call_info);
}

#[cfg(test)]
mod test_replace_class2 {
    use self::test_case;
    use super::{assert_eq, *};

    #[test_case(FeatureContract::SierraTestContract; "Native")]
    #[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
    fn undeclared_class_hash(test_contract: FeatureContract) {
        let mut state = create_deploy_test_state(test_contract);
        let entry_point_call = CallEntryPoint {
            calldata: calldata![stark_felt!(1234_u16)],
            entry_point_selector: selector_from_name("test_replace_class"),
            ..trivial_external_entry_point()
        };

        let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
        assert!(error.contains("is not declared"));
    }

    #[test_case(FeatureContract::SierraTestContract; "Native")]
    #[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
    fn cairo0_class_hash(test_contract: FeatureContract) {
        let mut state = create_deploy_test_state(test_contract);

        let v0_class_hash = class_hash!(5678_u16);
        let v0_contract_class = ContractClassV0::from_file(TEST_EMPTY_CONTRACT_CAIRO0_PATH).into();
        state.set_contract_class(v0_class_hash, v0_contract_class).unwrap();

        let entry_point_call = CallEntryPoint {
            calldata: calldata![v0_class_hash.0],
            entry_point_selector: selector_from_name("test_replace_class"),
            ..trivial_external_entry_point()
        };
        let error = entry_point_call.execute_directly(&mut state).unwrap_err().to_string();
        assert!(error.contains("Cannot replace V1 class hash with V0 class hash"));
    }

    #[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // pass
    #[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 14450; "VM")] // pass
    fn positive_flow(test_contract: FeatureContract, gas_consumed: u64) {
        let mut state = create_deploy_test_state(test_contract);
        let contract_address = contract_address!(TEST_CONTRACT_ADDRESS);
        let current_class_hash = class_hash!(TEST_CLASS_HASH);

        assert_eq!(state.get_class_hash_at(contract_address).unwrap(), current_class_hash);

        let new_class_hash = class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH);
        let entry_point_call = CallEntryPoint {
            calldata: calldata![new_class_hash.0],
            entry_point_selector: selector_from_name("test_replace_class"),
            ..trivial_external_entry_point()
        };

        assert_eq!(
            entry_point_call.execute_directly(&mut state).unwrap().execution,
            CallExecution { gas_consumed, ..Default::default() }
        );
        assert_eq!(state.get_class_hash_at(contract_address).unwrap(), new_class_hash);
    }
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // including the relevant function causes failure due to gas processing
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 17210900; "VM")] // pass
fn test_secp256k1(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_secp256k1"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: expected_gas, ..Default::default() }
    );
}

// #[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // fails, not
// implemented in the NativeSyscallHandler (TODO)
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 27650390; "VM")] // pass
fn test_secp256r1(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let calldata = Calldata(vec![].into());
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_secp256r1"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution { gas_consumed: expected_gas, ..Default::default() }
    );
}

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")] // pass
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 37990; "VM")] // pass
fn test_send_message_to_l1(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let to_address = stark_felt!(1234_u16);
    let payload = vec![stark_felt!(2019_u16), stark_felt!(2020_u16), stark_felt!(2021_u16)];
    let calldata = Calldata(
        concat(vec![
            vec![
                to_address,
                // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the
                // convertion works.
                stark_felt!(u64::try_from(payload.len()).expect("Failed to convert usize to u64.")),
            ],
            payload.clone(),
        ])
        .into(),
    );
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_send_message_to_l1"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    let to_address = EthAddress::try_from(to_address).unwrap();
    let message = MessageToL1 { to_address, payload: L2ToL1Payload(payload) };

    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            l2_to_l1_messages: vec![OrderedL2ToL1Message { order: 0, message }],
            gas_consumed: expected_gas,
            ..Default::default()
        }
    );
}

#[test_case(
    class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
    calldata![
    stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
    ContractAddressSalt::default().0,            // Contract_address_salt.
    stark_felt!(0_u8),                           // Calldata length.
    stark_felt!(0_u8)                            // deploy_from_zero.
    ],
    calldata![],
    None ;
    "No constructor: Positive flow"
)] // pass
#[test_case(
    class_hash!(TEST_EMPTY_CONTRACT_CLASS_HASH),
    calldata![
        stark_felt!(TEST_EMPTY_CONTRACT_CLASS_HASH), // Class hash.
        ContractAddressSalt::default().0,            // Contract_address_salt.
        stark_felt!(2_u8),                           // Calldata length.
        stark_felt!(2_u8),                           // Calldata: address.
        stark_felt!(1_u8),                           // Calldata: value.
        stark_felt!(0_u8)                            // deploy_from_zero.
    ],
    calldata![
        stark_felt!(2_u8),                           // Calldata: arg1.
        stark_felt!(1_u8)                            // Calldata: arg2.
    ],
    Some(FAILED_TO_EXECUTE_CALL);
    "No constructor: Negative flow: nonempty calldata")] // pass
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(1_u8),                // Calldata: arg1.
        stark_felt!(1_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ],
    calldata![
        stark_felt!(1_u8),                // Calldata: arg1.
        stark_felt!(1_u8)                 // Calldata: arg2.
    ],
    None;
    "With constructor: Positive flow")] // pass
#[test_case(
    class_hash!(TEST_CLASS_HASH),
    calldata![
        stark_felt!(TEST_CLASS_HASH),     // Class hash.
        ContractAddressSalt::default().0, // Contract_address_salt.
        stark_felt!(2_u8),                // Calldata length.
        stark_felt!(3_u8),                // Calldata: arg1.
        stark_felt!(3_u8),                // Calldata: arg2.
        stark_felt!(0_u8)                 // deploy_from_zero.
    ],
    calldata![
        stark_felt!(3_u8),                // Calldata: arg1.
        stark_felt!(3_u8)                 // Calldata: arg2.
    ],
    Some(FAILED_TO_EXECUTE_CALL);
    "With constructor: Negative flow: deploy to the same address")
] // pass
fn test_deploy(
    class_hash: ClassHash,
    calldata: Calldata,
    constructor_calldata: Calldata,
    expected_error: Option<&str>,
) {
    let mut state = create_deploy_test_state(FeatureContract::SierraTestContract);
    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_deploy"),
        calldata,
        ..trivial_external_entry_point()
    };

    if let Some(expected_error) = expected_error {
        let execution_result = entry_point_call.execute_directly(&mut state);
        let call_info = execution_result.unwrap().execution;
        let retdata = Retdata(vec![stark_felt!(expected_error)]);
        assert_eq!(
            call_info,
            CallExecution {
                gas_consumed: NATIVE_GAS_PLACEHOLDER,
                failed: true,
                retdata,
                ..Default::default()
            }
        );
        return;
    }

    // No errors expected.
    let contract_address = calculate_contract_address(
        ContractAddressSalt::default(),
        class_hash,
        &constructor_calldata,
        contract_address!(TEST_CONTRACT_ADDRESS),
    )
    .unwrap();

    let deploy_call = &entry_point_call.execute_directly(&mut state).unwrap().inner_calls[0];

    assert_eq!(deploy_call.call.storage_address, contract_address);

    let mut retdata = retdata![];
    let gas_consumed = if constructor_calldata.0.is_empty() {
        0
    } else {
        retdata.0.push(constructor_calldata.0[0]);
        NATIVE_GAS_PLACEHOLDER
    };

    assert_eq!(
        deploy_call.execution,
        CallExecution { retdata, gas_consumed, ..CallExecution::default() }
    );

    assert_eq!(state.get_class_hash_at(contract_address).unwrap(), class_hash);
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
