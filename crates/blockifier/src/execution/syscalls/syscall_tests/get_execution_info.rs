use std::collections::BTreeMap;

use cairo_felt::Felt252;
use num_traits::Pow;
use starknet_api::core::ChainId;
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, Fee, PaymasterData, Resource, ResourceBounds,
    ResourceBoundsMapping, Tip, TransactionHash, TransactionVersion,
};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::execution::syscalls::hint_processor::{L1_GAS, L2_GAS};
use crate::execution::syscalls::syscall_tests::{
    assert_consistent_contract_version, verify_compiler_version,
};
use crate::nonce;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    trivial_external_entry_point_with_address, CairoVersion, BALANCE, CHAIN_ID_NAME,
    CURRENT_BLOCK_NUMBER, CURRENT_BLOCK_NUMBER_FOR_VALIDATE, CURRENT_BLOCK_TIMESTAMP,
    CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    CommonAccountFields, CurrentTransactionInfo, DeprecatedTransactionInfo, TransactionInfo,
};

#[test_case(
    FeatureContract::SierraExecutionInfoV1Contract,
    ExecutionMode::Validate,
    TransactionVersion::ONE,
    false;
    "Native [V1]: Validate execution mode: block info fields should be zeroed. Transaction V1.")]
#[test_case(
    FeatureContract::SierraExecutionInfoV1Contract,
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Native [V1]: Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    FeatureContract::SierraExecutionInfoV1Contract,
    ExecutionMode::Validate,
    TransactionVersion::THREE,
    false;
    "Native [V1]: Validate execution mode: block info fields should be zeroed. Transaction V3.")]
#[test_case(
    FeatureContract::SierraExecutionInfoV1Contract,
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Native [V1]: Execute execution mode: block info should be as usual. Transaction V3.")]
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Validate,
    TransactionVersion::ONE,
    false;
    "Native: Validate execution mode: block info fields should be zeroed. Transaction V1.")]
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Native: Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Validate,
    TransactionVersion::THREE,
    false;
    "Native: Validate execution mode: block info fields should be zeroed. Transaction V3.")]
#[test_case(
    FeatureContract::SierraTestContract,
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Native: Execute execution mode: block info should be as usual. Transaction V3.")]
// TODO Native
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Validate,
    TransactionVersion::ONE,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V1.")]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Validate,
    TransactionVersion::THREE,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V3.")]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Execute execution mode: block info should be as usual. Transaction V3.")]
#[test_case(
    FeatureContract::LegacyTestContract,
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V1.")]
#[test_case(
    FeatureContract::LegacyTestContract,
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V3.")]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    true;
    "Execute execution mode: block info should be as usual. Transaction V3. Query.")]
fn test_get_execution_info(
    test_contract: FeatureContract,
    execution_mode: ExecutionMode,
    mut version: TransactionVersion,
    only_query: bool,
) {
    let state = &mut test_state(&ChainInfo::create_for_testing(), BALANCE, &[(test_contract, 1)]);
    assert_consistent_contract_version(test_contract, state);
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

    let test_contract_address = test_contract.get_instance_address(0);

    let expected_unsupported_fields = match test_contract {
        FeatureContract::LegacyTestContract => {
            verify_compiler_version(test_contract, "2.1.0");
            vec![]
        }
        _ => {
            vec![
                StarkFelt::ZERO, // Tip.
                StarkFelt::ZERO, // Paymaster data.
                StarkFelt::ZERO, // Nonce DA.
                StarkFelt::ZERO, // Fee DA.
                StarkFelt::ZERO, // Account data.
            ]
        }
    };

    if only_query {
        let simulate_version_base = Pow::pow(Felt252::from(2_u8), QUERY_VERSION_BASE_BIT);
        let query_version = simulate_version_base + stark_felt_to_felt(version.0);
        version = TransactionVersion(felt_to_stark_felt(&query_version));
    }

    let tx_hash = TransactionHash(stark_felt!(1991_u16));
    let max_fee = Fee(42);
    let nonce = nonce!(3_u16);
    let sender_address = test_contract_address;

    let max_amount = Fee(13);
    let max_price_per_unit = Fee(61);

    let expected_resource_bounds: Vec<StarkFelt> = match (test_contract, version) {
        (FeatureContract::LegacyTestContract, _) => vec![],
        (_, TransactionVersion::ONE) => vec![
            stark_felt!(0_u16), // Length of resource bounds array.
        ],
        (_, _) => vec![
            StarkFelt::from(2u32),             // Length of ResourceBounds array.
            stark_felt!(L1_GAS),               // Resource.
            stark_felt!(max_amount.0),         // Max amount.
            stark_felt!(max_price_per_unit.0), // Max price per unit.
            stark_felt!(L2_GAS),               // Resource.
            StarkFelt::ZERO,                   // Max amount.
            StarkFelt::ZERO,                   // Max price per unit.
        ],
    };

    let expected_tx_info: Vec<StarkFelt>;
    let tx_info: TransactionInfo;
    match version {
        TransactionVersion::ONE => {
            expected_tx_info = vec![
                version.0,                                                  // Transaction version.
                *sender_address.0.key(),                                    // Account address.
                stark_felt!(max_fee.0),                                     // Max fee.
                StarkFelt::ZERO,                                            // Signature.
                tx_hash.0,                                                  // Transaction hash.
                stark_felt!(&*ChainId(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
                nonce.0,                                                    // Nonce.
            ];

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
        }
        _ => {
            expected_tx_info = vec![
                version.0,                                                  // Transaction version.
                *sender_address.0.key(),                                    // Account address.
                StarkFelt::ZERO,                                            // Max fee.
                StarkFelt::ZERO,                                            // Signature.
                tx_hash.0,                                                  // Transaction hash.
                stark_felt!(&*ChainId(CHAIN_ID_NAME.to_string()).as_hex()), // Chain ID.
                nonce.0,                                                    // Nonce.
            ];

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
                        // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why
                        // the convertion works.
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
    }

    let entry_point_selector = selector_from_name("test_get_execution_info");
    let expected_call_info = vec![
        stark_felt!(0_u16),                  // Caller address.
        *test_contract_address.0.key(),      // Storage address.
        stark_felt!(entry_point_selector.0), // Entry point selector.
    ];
    let entry_point_call = CallEntryPoint {
        entry_point_selector,
        code_address: None,
        calldata: Calldata(
            [
                expected_block_info.to_vec(),
                expected_tx_info,
                if let FeatureContract::SierraExecutionInfoV1Contract = test_contract {
                    vec![]
                } else {
                    expected_resource_bounds
                        .into_iter()
                        .chain(expected_unsupported_fields)
                        .collect()
                },
                expected_call_info,
            ]
            .concat()
            .into(),
        ),
        ..trivial_external_entry_point_with_address(test_contract_address)
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
    assert_consistent_contract_version(test_contract, state);
}
