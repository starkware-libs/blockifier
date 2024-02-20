use rstest::rstest;
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::execution::call_info::{
    CallExecution, CallInfo, ExecutionSummary, ExecutionSummaryParameters, OrderedEvent,
};
use crate::transaction::objects::TransactionExecutionInfo;

#[rstest]
#[case(0, 0)]
#[case(0, 2)]
#[case(1, 3)]
#[case(2, 0)]
// TODO(Ayelet, 20/02/2024): Add test with nested inner calls.
fn test_transaction_execution_info_with_different_event_scenarios(
    #[case] num_of_execute_events: usize,
    #[case] num_of_inner_calls: usize,
) {
    fn call_info_with_x_events(num_of_events: usize, num_of_inner_calls: usize) -> CallInfo {
        CallInfo {
            execution: CallExecution {
                events: (0..num_of_events).map(|_i| OrderedEvent::default()).collect(),
                ..Default::default()
            },
            inner_calls: (0..num_of_inner_calls).map(|_i| call_info_with_x_events(1, 0)).collect(),
            ..Default::default()
        }
    }

    let num_of_validate_events = 2;
    let num_of_fee_transfer_events = 1;

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(num_of_validate_events, 0)),
        execute_call_info: Some(call_info_with_x_events(num_of_execute_events, num_of_inner_calls)),
        fee_transfer_call_info: Some(call_info_with_x_events(num_of_fee_transfer_events, 0)),
        ..Default::default()
    };

    assert_eq!(
        transaction_execution_info.get_number_of_events(),
        num_of_validate_events
            + num_of_execute_events
            + num_of_fee_transfer_events
            + num_of_inner_calls
    );
}

#[rstest]
#[case(
    ExecutionSummaryParameters::new(1, ClassHash(stark_felt!("0x1")), "0x1", "0x1"),
    ExecutionSummaryParameters::new(2, ClassHash(stark_felt!("0x2")), "0x2", "0x2"),
    ExecutionSummaryParameters::new(3, ClassHash(stark_felt!("0x3")), "0x3", "0x3")
)]
fn test_summarize(
    #[case] validate_params: ExecutionSummaryParameters,
    #[case] execute_params: ExecutionSummaryParameters,
    #[case] fee_transfer_params: ExecutionSummaryParameters,
) {
    let validate_call_info = CallInfo::create_call_info_for_testing(&validate_params);
    let execute_call_info = CallInfo::create_call_info_for_testing(&execute_params);
    let fee_transfer_call_info = CallInfo::create_call_info_for_testing(&fee_transfer_params);

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(validate_call_info),
        execute_call_info: Some(execute_call_info),
        fee_transfer_call_info: Some(fee_transfer_call_info),
        ..Default::default()
    };

    let expected_summary = ExecutionSummary {
        executed_class_hashes: vec![
            validate_params.class_hash,
            execute_params.class_hash,
            fee_transfer_params.class_hash,
        ]
        .into_iter()
        .collect(),
        visited_storage_entries: vec![
            (validate_params.storage_address, validate_params.storage_key),
            (execute_params.storage_address, execute_params.storage_key),
            (fee_transfer_params.storage_address, fee_transfer_params.storage_key),
        ]
        .into_iter()
        .collect(),
        n_events: validate_params.num_of_events
            + execute_params.num_of_events
            + fee_transfer_params.num_of_events,
    };

    // Call the summarize method
    let actual_summary = transaction_execution_info.summarize();

    // Compare the actual result with the expected result
    assert_eq!(actual_summary.executed_class_hashes, expected_summary.executed_class_hashes);
    assert_eq!(actual_summary.visited_storage_entries, expected_summary.visited_storage_entries);
    assert_eq!(actual_summary.n_events, expected_summary.n_events);
}
