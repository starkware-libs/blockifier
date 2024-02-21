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

fn call_info_with_x_events(n_events: usize, n_inner_calls: usize) -> CallInfo {
    CallInfo {
        execution: CallExecution {
            events: (0..n_events).map(|_| OrderedEvent::default()).collect(),
            ..Default::default()
        },
        inner_calls: (0..n_inner_calls).map(|_| call_info_with_x_events(1, 0)).collect(),
        ..shared_call_info()
    }
}

fn call_info_with_deep_inner_calls(
    n_events: usize,
    n_inner_calls: usize,
    n_events_of_each_inner_call: usize,
    n_inner_calls_of_each_inner_call: usize,
) -> CallInfo {
    let inner_calls = (0..n_inner_calls)
        .map(|_| {
            call_info_with_x_events(n_events_of_each_inner_call, n_inner_calls_of_each_inner_call)
        })
        .collect();

    CallInfo {
        inner_calls,
        execution: CallExecution {
            events: (0..n_events).map(|_| OrderedEvent::default()).collect(),
            ..Default::default()
        },
        ..shared_call_info()
    }
}

#[rstest]
#[case(0, 0)]
#[case(0, 2)]
#[case(1, 3)]
#[case(2, 0)]
fn test_events_counter_in_transaction_execution_info(
    #[case] n_execute_events: usize,
    #[case] n_inner_calls: usize,
) {
    let n_validate_events = 2;
    let n_fee_transfer_events = 1;

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(n_validate_events, 0)),
        execute_call_info: Some(call_info_with_x_events(n_execute_events, n_inner_calls)),
        fee_transfer_call_info: Some(call_info_with_x_events(n_fee_transfer_events, 0)),
        ..Default::default()
    };

    assert_eq!(
        transaction_execution_info.summarize().n_events,
        n_validate_events + n_execute_events + n_fee_transfer_events + n_inner_calls
    );
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(20)]
fn test_events_counter_in_transaction_execution_info_with_inner_call_info(
    #[case] n_execute_events: usize,
) {
    let n_fee_transfer_events = 2;
    let n_inner_calls = 3;
    let n_execution_events = 1;
    let n_events_for_each_inner_call = 2;
    let n_inner_calls_of_each_inner_call = 1;

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_deep_inner_calls(
            n_execution_events,
            n_inner_calls,
            n_events_for_each_inner_call,
            n_inner_calls_of_each_inner_call,
        )),
        execute_call_info: Some(call_info_with_x_events(n_execute_events, 0)),
        fee_transfer_call_info: Some(call_info_with_x_events(n_fee_transfer_events, 0)),
        ..Default::default()
    };

    assert_eq!(
        transaction_execution_info.summarize().n_events,
        n_execute_events
            + n_fee_transfer_events
            + n_execution_events
            + n_inner_calls
            + n_events_for_each_inner_call * n_inner_calls
    );
}
