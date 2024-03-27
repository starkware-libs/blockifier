use std::collections::BTreeMap;

use cairo_felt::Felt252;
use num_traits::Pow;
use starknet_api::core::{ChainId, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{
    AccountDeploymentData, Calldata, Fee, PaymasterData, Resource, ResourceBounds,
    ResourceBoundsMapping, Tip, TransactionHash, TransactionVersion,
};
use test_case::test_case;

use super::verify_compiler_version;
use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::common_hints::ExecutionMode;
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::execution::syscalls::hint_processor::{L1_GAS, L2_GAS};
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{
    trivial_external_entry_point, CairoVersion, BALANCE, CHAIN_ID_NAME, CURRENT_BLOCK_NUMBER,
    CURRENT_BLOCK_NUMBER_FOR_VALIDATE, CURRENT_BLOCK_TIMESTAMP,
    CURRENT_BLOCK_TIMESTAMP_FOR_VALIDATE, TEST_SEQUENCER_ADDRESS,
};
use crate::transaction::constants::QUERY_VERSION_BASE_BIT;
use crate::transaction::objects::{
    CommonAccountFields, CurrentTransactionInfo, DeprecatedTransactionInfo, TransactionInfo,
};

// TODO Native
// #[test_case(
//     FeatureContract::SierraTestContract,
//     ExecutionMode::Validate,
//     TransactionVersion::ONE,
//     false;
//     "Native. Validate execution mode: block info fields should be zeroed. Transaction V1."
// )]
// #[test_case(
//     FeatureContract::SierraTestContract,
//     ExecutionMode::Execute,
//     TransactionVersion::ONE,
//     false;
//     "Native. Execute execution mode: block info fields should be zeroed. Transaction V1."
// )]
// #[test_case(
//     FeatureContract::SierraTestContract,
//     ExecutionMode::Validate,
//     TransactionVersion::THREE,
//     false;
//     "Native. Validate execution mode: block info fields should be zeroed. Transaction V3."
// )]
// #[test_case(
//     FeatureContract::SierraTestContract,
//     ExecutionMode::Execute,
//     TransactionVersion::THREE,
//     false;
//     "Native. Execute execution mode: block info fields should be zeroed. Transaction V3."
// )]
// #[test_case(
//     FeatureContract::SierraTestContract,
//     ExecutionMode::Execute,
//     TransactionVersion::THREE,
//     true;
//     "Native. Execute execution mode: block info should be as usual. Transaction V3. Query."
// )]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Validate,
    TransactionVersion::ONE,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V1."
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Execute execution mode: block info fields should be zeroed. Transaction V1."
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Validate,
    TransactionVersion::THREE,
    false;
    "Validate execution mode: block info fields should be zeroed. Transaction V3."
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Execute execution mode: block info fields should be zeroed. Transaction V3."
)]
#[test_case(
    FeatureContract::TestContract(CairoVersion::Cairo1),
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    true;
    "Execute execution mode: block info should be as usual. Transaction V3. Query."
)]
#[test_case(
    FeatureContract::LegacyTestContract,
    ExecutionMode::Execute,
    TransactionVersion::ONE,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V1."
)]
#[test_case(
    FeatureContract::LegacyTestContract,
    ExecutionMode::Execute,
    TransactionVersion::THREE,
    false;
    "Legacy contract. Execute execution mode: block info should be as usual. Transaction V3."
)]
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
        _ => std::panic!("unexpected feature contract"),
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
