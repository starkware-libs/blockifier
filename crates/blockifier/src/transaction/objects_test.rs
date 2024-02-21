use rstest::rstest;
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent};
use crate::execution::entry_point::CallEntryPoint;
use crate::transaction::objects::TransactionExecutionInfo;

fn shared_call_info() -> CallInfo {
    CallInfo {
        call: CallEntryPoint {
            class_hash: Some(ClassHash(stark_felt!("0x1"))),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn call_info_with_x_events(num_of_events: usize, num_of_inner_calls: usize) -> CallInfo {
    CallInfo {
        execution: CallExecution {
            events: (0..num_of_events).map(|_| OrderedEvent::default()).collect(),
            ..Default::default()
        },
        inner_calls: (0..num_of_inner_calls).map(|_| call_info_with_x_events(1, 0)).collect(),
        ..shared_call_info()
    }
}

fn call_info_with_deep_inner_call() -> CallInfo {
    let inner_inner_call = call_info_with_x_events(0, 1);
    let inner_call = CallInfo { inner_calls: vec![inner_inner_call], ..shared_call_info() };

    CallInfo {
        inner_calls: vec![inner_call],
        execution: CallExecution { events: vec![OrderedEvent::default()], ..Default::default() },
        ..shared_call_info()
    }
}

#[rstest]
#[case(0, 0)]
#[case(0, 2)]
#[case(1, 3)]
#[case(2, 0)]
fn test_events_counter_in_transaction_execution_info(
    #[case] num_of_execute_events: usize,
    #[case] num_of_inner_calls: usize,
) {
    let num_of_validate_events = 2;
    let num_of_fee_transfer_events = 1;

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(num_of_validate_events, 0)),
        execute_call_info: Some(call_info_with_x_events(num_of_execute_events, num_of_inner_calls)),
        fee_transfer_call_info: Some(call_info_with_x_events(num_of_fee_transfer_events, 0)),
        ..Default::default()
    };

    assert_eq!(
        transaction_execution_info.summarize().n_events,
        num_of_validate_events
            + num_of_execute_events
            + num_of_fee_transfer_events
            + num_of_inner_calls
    );
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(20)]
fn test_events_counter_in_transaction_execution_info_with_inner_call_info(
    #[case] num_of_execute_events: usize,
) {
    let num_of_fee_transfer_events = 2;

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_deep_inner_call()),
        execute_call_info: Some(call_info_with_x_events(num_of_execute_events, 0)),
        fee_transfer_call_info: Some(call_info_with_x_events(num_of_fee_transfer_events, 0)),
        ..Default::default()
    };

    let number_of_inner_calls_events = 2;

    assert_eq!(
        transaction_execution_info.summarize().n_events,
        num_of_execute_events + num_of_fee_transfer_events + number_of_inner_calls_events
    );
}
