use rstest::rstest;
use starknet_api::core::ClassHash;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent};
use crate::execution::entry_point::CallEntryPoint;
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
            call: CallEntryPoint {
                class_hash: Some(ClassHash(stark_felt!("0x1"))),
                ..Default::default()
            },
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
        transaction_execution_info.summarize().n_events,
        num_of_validate_events
            + num_of_execute_events
            + num_of_fee_transfer_events
            + num_of_inner_calls
    );
}
