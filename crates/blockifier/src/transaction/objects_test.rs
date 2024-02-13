use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent};
use crate::transaction::objects::TransactionExecutionInfo;

#[rstest]
#[case(0, 0, 0, 0)]
#[case(1, 0, 3, 2)]
#[case(1, 1, 4, 1)]
#[case(0, 1, 2, 3)]
#[case(2, 2, 10, 0)]
fn test_transaction_execution_info_with_different_event_scenarios2(
    #[case] num_of_validate_events: usize,
    #[case] num_of_execute_events: usize,
    #[case] num_of_fee_transfer_events: usize,
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

    let transaction_execution_info = TransactionExecutionInfo {
        validate_call_info: Some(call_info_with_x_events(
            num_of_validate_events,
            num_of_inner_calls,
        )),
        execute_call_info: Some(call_info_with_x_events(num_of_execute_events, 0)),
        fee_transfer_call_info: Some(call_info_with_x_events(num_of_fee_transfer_events, 0)),
        ..Default::default()
    };

    assert_eq!(
        transaction_execution_info.get_tx_number_of_events(),
        num_of_validate_events
            + num_of_execute_events
            + num_of_fee_transfer_events
            + num_of_inner_calls
    );
}
