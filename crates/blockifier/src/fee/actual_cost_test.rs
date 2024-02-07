use rstest::{fixture, rstest};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::L2ToL1Payload;

use crate::execution::call_info::{CallExecution, CallInfo, MessageToL1, OrderedL2ToL1Message};
use crate::fee::actual_cost::ActualCostBuilder;
use crate::fee::eth_gas_constants;
use crate::fee::gas_usage::{
    get_consumed_message_to_l2_emissions_cost, get_da_gas_cost,
    get_log_message_to_l1_emissions_cost, get_message_segment_length,
};
use crate::state::cached_state::StateChangesCount;
use crate::transaction::objects::GasVector;
use crate::utils::{u128_from_usize, usize_from_u128};
use crate::versioned_constants::VersionedConstants;

#[fixture]
fn versioned_constants() -> &'static VersionedConstants {
    VersionedConstants::latest_constants()
}

/// This test goes over six cases. In each case, we calculate the gas usage given the parameters.
/// We then perform the same calculation manually, each time using only the relevant parameters.
/// The six cases are:
///     1. An empty transaction.
///     2. A DeployAccount transaction.
///     3. An L1 handler.
///     4. A transaction with L2-to-L1 messages.
///     5. A transaction that modifies the storage.
///     6. A combination of cases 3. 4. and 5.
// TODO(Aner, 29/01/24) Refactor with assert on GasVector objects.
// TODO(Aner, 29/01/24) Refactor to replace match with if when formatting is nicer
#[rstest]
fn test_calculate_tx_gas_usage_basic(
    #[values(false, true)] use_kzg_da: bool,
    versioned_constants: &VersionedConstants,
) {
    // An empty transaction (a theoretical case for sanity check).
    // let versioned_constants = VersionedConstants::default();
    let empty_tx_gas_usage_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        std::iter::empty(),
        StateChangesCount::default(),
        None,
        use_kzg_da,
    )
    .unwrap();
    assert_eq!(empty_tx_gas_usage_vector, GasVector { l1_gas: 0, l1_data_gas: 0 });

    // DeployAccount.

    let deploy_account_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 1,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };

    // Manual calculation.
    let manual_starknet_gas_usage = 0;
    let manual_gas_vector = GasVector { l1_gas: manual_starknet_gas_usage, ..Default::default() }
        + get_da_gas_cost(deploy_account_state_changes_count, use_kzg_da);

    let deploy_account_gas_usage_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        std::iter::empty(),
        deploy_account_state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();
    assert_eq!(manual_gas_vector, deploy_account_gas_usage_vector);

    // L1 handler.

    let l1_handler_payload_size = 4;
    let l1_handler_gas_usage_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        std::iter::empty(),
        StateChangesCount::default(),
        Some(l1_handler_payload_size),
        use_kzg_da,
    )
    .unwrap();

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&[], Some(l1_handler_payload_size));
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + eth_gas_constants::GAS_PER_COUNTER_DECREASE
        + usize_from_u128(
            get_consumed_message_to_l2_emissions_cost(Some(l1_handler_payload_size)).l1_gas,
        )
        .unwrap();
    let manual_sharp_gas_usage =
        message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;
    let manual_gas_computation = GasVector {
        l1_gas: u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage).unwrap(),
        l1_data_gas: 0,
    };

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
        .flat_map(|call_info| call_info.get_sorted_l2_to_l1_payload_lengths().unwrap())
        .collect();

    let l2_to_l1_state_changes_count = StateChangesCount {
        n_storage_updates: 0,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: 1,
    };
    let l2_to_l1_messages_gas_usage_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        call_infos_iter.clone(),
        l2_to_l1_state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();

    // Manual calculation.
    let message_segment_length = get_message_segment_length(&l2_to_l1_payload_lengths, None);
    let n_l2_to_l1_messages = l2_to_l1_payload_lengths.len();
    let manual_starknet_gas_usage = message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
        + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
        + usize_from_u128(get_log_message_to_l1_emissions_cost(&l2_to_l1_payload_lengths).l1_gas)
            .unwrap();
    let manual_sharp_gas_usage = message_segment_length
        * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD
        + usize_from_u128(get_da_gas_cost(l2_to_l1_state_changes_count, use_kzg_da).l1_gas)
            .unwrap();
    let manual_sharp_blob_gas_usage =
        get_da_gas_cost(l2_to_l1_state_changes_count, use_kzg_da).l1_data_gas;
    let manual_gas_computation = GasVector {
        l1_gas: u128_from_usize(manual_starknet_gas_usage + manual_sharp_gas_usage).unwrap(),
        l1_data_gas: manual_sharp_blob_gas_usage,
    };

    assert_eq!(l2_to_l1_messages_gas_usage_vector, manual_gas_computation);

    // Any calculation with storage writings.

    let n_modified_contracts = 7;
    let n_storage_updates = 11;
    let storage_writes_state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts,
    };
    let storage_writings_gas_usage_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        std::iter::empty(),
        storage_writes_state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();

    // Manual calculation.
    let manual_gas_computation = get_da_gas_cost(storage_writes_state_changes_count, use_kzg_da);

    assert_eq!(manual_gas_computation, storage_writings_gas_usage_vector);

    // Combined case of an L1 handler, L2-to-L1 messages and storage writes.
    let combined_state_changes_count = StateChangesCount {
        n_storage_updates: storage_writes_state_changes_count.n_storage_updates,
        n_class_hash_updates: 0,
        n_compiled_class_hash_updates: 0,
        n_modified_contracts: storage_writes_state_changes_count.n_modified_contracts
            + l2_to_l1_state_changes_count.n_modified_contracts,
    };
    let gas_usage_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        call_infos_iter,
        combined_state_changes_count,
        Some(l1_handler_payload_size),
        use_kzg_da,
    )
    .unwrap();

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
        + u128_from_usize(fee_balance_discount).unwrap(),
        // Expected blob gas usage is from data availability only.
        l1_data_gas: get_da_gas_cost(combined_state_changes_count, use_kzg_da).l1_data_gas,
    };

    assert_eq!(expected_gas_vector, gas_usage_vector);
}

use starknet_api::core::Nonce;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::context::BlockContext;
use crate::invoke_tx_args;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{create_calldata, default_invoke_tx_args, CairoVersion, BALANCE, MAX_FEE};
use crate::transaction::constants;
use crate::transaction::objects::HasRelatedFeeType;
use crate::transaction::test_utils::account_invoke_tx;
use crate::transaction::transactions::ExecutableTransaction;

// Test that we exclude the fee token contract modification and adds the account’s balance change
// in the state changes.
// TODO(Aner, 21/01/24) modify for 4844 (taking blob_gas into account).
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

    let account_tx = account_invoke_tx(default_invoke_tx_args(
        account_contract_address,
        test_contract.get_instance_address(0),
    ));
    let fee_token_address = chain_info.fee_token_address(&account_tx.fee_type());
    let tx_execution_info = account_tx.execute(state, block_context, true, true).unwrap();

    let n_storage_updates = 1; // For the account balance update.
    let n_modified_contracts = 1;
    let state_changes_count = StateChangesCount {
        n_storage_updates,
        n_class_hash_updates: 0,
        n_modified_contracts,
        n_compiled_class_hash_updates: 0,
    };

    let gas_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        std::iter::empty(),
        state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();
    let GasVector { l1_gas: l1_gas_usage, l1_data_gas: l1_blob_gas_usage } = gas_vector;
    assert_eq!(
        u128_from_usize(tx_execution_info.actual_resources.gas_usage()).unwrap(),
        l1_gas_usage
    );
    assert_eq!(
        u128_from_usize(tx_execution_info.actual_resources.blob_gas_usage()).unwrap(),
        l1_blob_gas_usage
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
        nonce: Nonce(stark_felt!(1_u8)),
    });

    let tx_execution_info = account_tx.execute(state, block_context, true, true).unwrap();
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

    let gas_vector = ActualCostBuilder::calculate_tx_gas_usage_vector(
        versioned_constants,
        std::iter::empty(),
        state_changes_count,
        None,
        use_kzg_da,
    )
    .unwrap();
    let GasVector { l1_gas: l1_gas_usage, l1_data_gas: l1_blob_gas_usage } = gas_vector;
    assert_eq!(
        u128_from_usize(tx_execution_info.actual_resources.gas_usage()).unwrap(),
        l1_gas_usage
    );
    assert_eq!(
        u128_from_usize(tx_execution_info.actual_resources.blob_gas_usage()).unwrap(),
        l1_blob_gas_usage
    );
}
