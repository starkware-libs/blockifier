use rstest::{fixture, rstest};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, L2ToL1Payload, TransactionVersion};

use crate::context::BlockContext;
use crate::execution::call_info::{CallExecution, CallInfo, MessageToL1, OrderedL2ToL1Message};
use crate::fee::eth_gas_constants;
use crate::fee::gas_usage::{
    get_consumed_message_to_l2_emissions_cost, get_log_message_to_l1_emissions_cost,
    get_message_segment_length,
};
use crate::state::cached_state::StateChangesCount;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{create_calldata, create_trivial_calldata, CairoVersion, BALANCE, MAX_FEE};
use crate::transaction::constants;
use crate::transaction::objects::{GasVector, HasRelatedFeeType, StarknetResources};
use crate::transaction::test_utils::{account_invoke_tx, calculate_class_info_for_testing};
use crate::transaction::transactions::ExecutableTransaction;
use crate::utils::{u128_from_usize, usize_from_u128};
use crate::versioned_constants::VersionedConstants;
use crate::{invoke_tx_args, nonce};
#[fixture]
fn versioned_constants() -> &'static VersionedConstants {
    VersionedConstants::latest_constants()
}

/// This test goes over seven cases. In each case, we calculate the gas usage given the parameters.
/// We then perform the same calculation manually, each time using only the relevant parameters.
/// The seven cases are:
///     1. An empty transaction.
///     2. A Declare transaction.
///     3. A DeployAccount transaction.
///     4. An L1 handler.
///     5. A transaction with L2-to-L1 messages.
///     6. A transaction that modifies the storage.
///     7. A combination of cases 4. 5. and 6.
// TODO(Aner, 29/01/24) Refactor with assert on GasVector objects.
// TODO(Aner, 29/01/24) Refactor to replace match with if when formatting is nicer
#[rstest]
fn test_calculate_tx_gas_usage_basic<'a>(#[values(false, true)] use_kzg_da: bool) {
    // An empty transaction (a theoretical case for sanity check).
    let versioned_constants = VersionedConstants::default();
    let empty_tx_starknet_resources = StarknetResources::default();
    let empty_tx_gas_usage_vector =
        empty_tx_starknet_resources.to_gas_vector(&versioned_constants, use_kzg_da);
    assert_eq!(empty_tx_gas_usage_vector, GasVector::default());

    // Declare.
    for cairo_version in [CairoVersion::Cairo0, CairoVersion::Cairo1] {
        let empty_contract = FeatureContract::Empty(cairo_version).get_class();
        let class_info = calculate_class_info_for_testing(empty_contract);
        let declare_tx_starknet_resources = StarknetResources::new(
            0,
            0,
            class_info.code_size(),
            StateChangesCount::default(),
            None,
            std::iter::empty(),
        );
        let code_gas_cost = versioned_constants.l2_resource_gas_costs.gas_per_code_byte
            * u128_from_usize(
                (class_info.bytecode_length() + class_info.sierra_program_length())
                    * eth_gas_constants::WORD_WIDTH
                    + class_info.abi_length(),
            );
        let manual_gas_vector =
            GasVector { l1_gas: code_gas_cost.to_integer(), ..Default::default() };
        let declare_gas_usage_vector =
            declare_tx_starknet_resources.to_gas_vector(&versioned_constants, use_kzg_da);
        assert_eq!(manual_gas_vector, declare_gas_usage_vector);
    }

    // DeployAccount.

    let deploy_account_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 1,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };

    // Manual calculation.
    let calldata_length = 0;
    let signature_length = 2;
    let deploy_account_tx_starknet_resources = StarknetResources::new(
        calldata_length,
        signature_length,
        0,
        deploy_account_state_changes_count,
        None,
        std::iter::empty(),
    );
    let calldata_and_signature_gas_cost =
        versioned_constants.l2_resource_gas_costs.gas_per_data_felt
            * u128_from_usize(calldata_length + signature_length);
    let manual_starknet_gas_usage = calldata_and_signature_gas_cost.to_integer();
    let manual_gas_vector = GasVector { l1_gas: manual_starknet_gas_usage, ..Default::default() }
        + deploy_account_tx_starknet_resources.get_state_changes_cost(use_kzg_da);

    let deploy_account_gas_usage_vector =
        deploy_account_tx_starknet_resources.to_gas_vector(&versioned_constants, use_kzg_da);
    assert_eq!(manual_gas_vector, deploy_account_gas_usage_vector);

    // L1 handler.

    let l1_handler_payload_size = 4;
    let l1_handler_tx_starknet_resources = StarknetResources::new(
        l1_handler_payload_size,
        signature_length,
        0,
        StateChangesCount::default(),
        Some(l1_handler_payload_size),
        std::iter::empty(),
    );
    let l1_handler_gas_usage_vector =
        l1_handler_tx_starknet_resources.to_gas_vector(&versioned_constants, use_kzg_da);

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&[], Some(l1_handler_payload_size));
    let calldata_and_signature_gas_cost =
        versioned_constants.l2_resource_gas_costs.gas_per_data_felt
            * u128_from_usize(l1_handler_payload_size + signature_length);
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + eth_gas_constants::GAS_PER_COUNTER_DECREASE
        + usize_from_u128(
            get_consumed_message_to_l2_emissions_cost(Some(l1_handler_payload_size)).l1_gas,
        )
        .unwrap()
        + usize_from_u128(calldata_and_signature_gas_cost.to_integer()).unwrap();
    let manual_sharp_gas_usage =
        message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;
    let manual_gas_computation =
        GasVector::from_l1_gas(u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage));
    assert_eq!(l1_handler_gas_usage_vector, manual_gas_computation);

    // Any transaction with L2-to-L1 messages.

    let mut call_infos = Vec::new();
    for i in 0..4 {
        let payload_vec = vec![stark_felt!(0_u16); i];
        let call_info = CallInfo {
            execution: CallExecution {
                l2_to_l1_messages: vec![OrderedL2ToL1Message {
                    message: MessageToL1 {
                        payload: L2ToL1Payload(payload_vec),
                        ..Default::default()
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        call_infos.push(call_info);
    }
    // l2_to_l1_payload_lengths is [0, 1, 2, 3]
    let call_infos_iter = call_infos.iter();
    let l2_to_l1_payload_lengths: Vec<usize> = call_infos_iter
        .clone()
        .flat_map(|call_info| call_info.get_l2_to_l1_payload_lengths())
        .collect();

    let l2_to_l1_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };
    let l2_to_l1_starknet_resources = StarknetResources::new(
        0,
        0,
        0,
        l2_to_l1_state_changes_count,
        None,
        call_infos_iter.clone(),
    );

    let l2_to_l1_messages_gas_usage_vector =
        l2_to_l1_starknet_resources.to_gas_vector(&versioned_constants, use_kzg_da);

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&l2_to_l1_payload_lengths, None);
    let n_l2_to_l1_messages = l2_to_l1_payload_lengths.len();
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
        + usize_from_u128(get_log_message_to_l1_emissions_cost(&l2_to_l1_payload_lengths).l1_gas)
            .unwrap();
    let manual_sharp_gas_usage = message_segment_length
        * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD
        + usize_from_u128(l2_to_l1_starknet_resources.get_state_changes_cost(use_kzg_da).l1_gas)
            .unwrap();
    let manual_sharp_blob_gas_usage =
        l2_to_l1_starknet_resources.get_state_changes_cost(use_kzg_da).l1_data_gas;
    let manual_gas_computation = GasVector {
        l1_gas: u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage),
        l1_data_gas: manual_sharp_blob_gas_usage,
    };

    assert_eq!(l2_to_l1_messages_gas_usage_vector, manual_gas_computation);

    // Any calculation with storage writings.t

    let n_modified_contracts = 7;
    let n_storage_updates = 11;
    let storage_writes_state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts,
    };
    let storage_writes_starknet_resources = StarknetResources::new(
        0,
        0,
        0,
        storage_writes_state_changes_count,
        None,
        std::iter::empty(),
    );

    let storage_writings_gas_usage_vector =
        storage_writes_starknet_resources.to_gas_vector(&versioned_constants, use_kzg_da);

    // Manual calculation.
    let manual_gas_computation =
        storage_writes_starknet_resources.get_state_changes_cost(use_kzg_da);

    assert_eq!(manual_gas_computation, storage_writings_gas_usage_vector);

    // Combined case of an L1 handler, L2-to-L1 messages and storage writes.
    let combined_state_changes_count = StateChangesCount {
        n_storage_updates: storage_writes_state_changes_count.n_storage_updates,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: storage_writes_state_changes_count.n_modified_contracts
            + l2_to_l1_state_changes_count.n_modified_contracts,
    };
    let combined_cases_starknet_resources = StarknetResources::new(
        l1_handler_payload_size,
        signature_length,
        0,
        combined_state_changes_count,
        Some(l1_handler_payload_size),
        call_infos_iter.clone(),
    );

    let gas_usage_vector =
        combined_cases_starknet_resources.to_gas_vector(&versioned_constants, use_kzg_da);

    // Manual calculation.
    let fee_balance_discount = match use_kzg_da {
        true => 0,
        false => {
            eth_gas_constants::GAS_PER_MEMORY_WORD - eth_gas_constants::get_calldata_word_cost(12)
        }
    };

    let expected_gas_vector = GasVector {
        l1_gas: l1_handler_gas_usage_vector.l1_gas
        + l2_to_l1_messages_gas_usage_vector.l1_gas
        + storage_writings_gas_usage_vector.l1_gas
        // l2_to_l1_messages_gas_usage and storage_writings_gas_usage got a discount each, while
        // the combined calculation got it once.
        + u128_from_usize(fee_balance_discount),
        // Expected blob gas usage is from data availability only.
        l1_data_gas: combined_cases_starknet_resources
            .get_state_changes_cost(use_kzg_da)
            .l1_data_gas,
    };

    assert_eq!(expected_gas_vector, gas_usage_vector);
}

// Test that we exclude the fee token contract modification and adds the account’s balance change
// in the state changes.
// TODO(Aner, 21/01/24) modify for 4844 (taking blob_gas into account).
// TODO(Nimrod, 1/5/2024): Test regression w.r.t. all resources (including VM). (Only starknet
// resources are taken into account).
#[rstest]
fn test_calculate_tx_gas_usage(#[values(false, true)] use_kzg_da: bool) {
    let account_cairo_version = CairoVersion::Cairo0;
    let test_contract_cairo_version = CairoVersion::Cairo0;
    let block_context = &BlockContext::create_for_account_testing_with_kzg(use_kzg_da);
    let versioned_constants = &block_context.versioned_constants;
    let chain_info = &block_context.chain_info;
    let account_contract = FeatureContract::AccountWithoutValidations(account_cairo_version);
    let test_contract = FeatureContract::TestContract(test_contract_cairo_version);
    let account_contract_address = account_contract.get_instance_address(0);
    let state = &mut test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);

    let account_tx = account_invoke_tx(invoke_tx_args! {
        sender_address: account_contract_address,
        calldata: create_trivial_calldata(test_contract.get_instance_address(0)),
        max_fee: Fee(MAX_FEE),
    });
    let calldata_length = account_tx.calldata_length();
    let signature_length = account_tx.signature_length();
    let fee_token_address = chain_info.fee_token_address(&account_tx.fee_type());
    let tx_execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();

    let n_storage_updates = 1; // For the account balance update.
    let n_modified_contracts = 1;
    let state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_modified_contracts,
        n_compiled_class_hash_updates: 0,
    };
    let starknet_resources = StarknetResources::new(
        calldata_length,
        signature_length,
        0,
        state_changes_count,
        None,
        std::iter::empty(),
    );

    assert_eq!(
        starknet_resources.to_gas_vector(versioned_constants, use_kzg_da),
        tx_execution_info
            .actual_resources
            .starknet_resources
            .to_gas_vector(versioned_constants, use_kzg_da)
    );

    // A tx that changes the account and some other balance in execute.
    let some_other_account_address = account_contract.get_instance_address(17);
    let execute_calldata = create_calldata(
        fee_token_address,
        constants::TRANSFER_ENTRY_POINT_NAME,
        &[
            *some_other_account_address.0.key(), // Calldata: recipient.
            stark_felt!(2_u8),                   // Calldata: lsb amount.
            stark_felt!(0_u8),                   // Calldata: msb amount.
        ],
    );

    let account_tx = account_invoke_tx(invoke_tx_args! {
        max_fee: Fee(MAX_FEE),
        sender_address: account_contract_address,
        calldata: execute_calldata,
        version: TransactionVersion::ONE,
        nonce: nonce!(1_u8),
    });

    let calldata_length = account_tx.calldata_length();
    let signature_length = account_tx.signature_length();
    let tx_execution_info = account_tx.execute(state, block_context, true, true, None).unwrap();
    // For the balance update of the sender and the recipient.
    let n_storage_updates = 2;
    // Only the account contract modification (nonce update) excluding the fee token contract.
    let n_modified_contracts = 1;
    let state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_modified_contracts,
        n_compiled_class_hash_updates: 0,
    };

    let starknet_resources = StarknetResources::new(
        calldata_length,
        signature_length,
        0,
        state_changes_count,
        None,
        std::iter::empty(),
    );

    assert_eq!(
        starknet_resources.to_gas_vector(versioned_constants, use_kzg_da),
        tx_execution_info
            .actual_resources
            .starknet_resources
            .to_gas_vector(versioned_constants, use_kzg_da)
    );
}
