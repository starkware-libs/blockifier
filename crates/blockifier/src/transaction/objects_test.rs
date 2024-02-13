use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent};
use crate::transaction::objects::TransactionExecutionInfo;

#[test]
fn test_transaction_execution_info_with_different_event_scenarios() {
    fn call_info_with_x_events(num_of_events: usize) -> CallInfo {
        CallInfo {
            execution: CallExecution {
                events: (0..num_of_events).map(|_i| OrderedEvent::default()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    let transaction_execution_info_with_0_events = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(0)),
        execute_call_info: Some(call_info_with_x_events(0)),
        fee_transfer_call_info: Some(call_info_with_x_events(0)),
        ..Default::default()
    };

    assert_eq!(transaction_execution_info_with_0_events.get_call_infos_events_size(), 0);

    let transaction_execution_info_with_3_events = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(1)),
        execute_call_info: Some(call_info_with_x_events(2)),
        fee_transfer_call_info: Some(call_info_with_x_events(0)),
        ..Default::default()
    };

    assert_eq!(transaction_execution_info_with_3_events.get_call_infos_events_size(), 3);

    let transaction_execution_info_with_4_events = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(1)),
        execute_call_info: Some(call_info_with_x_events(1)),
        fee_transfer_call_info: Some(call_info_with_x_events(2)),
        ..Default::default()
    };

    assert_eq!(transaction_execution_info_with_4_events.get_call_infos_events_size(), 4);
}
