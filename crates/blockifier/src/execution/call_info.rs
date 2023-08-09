use std::collections::HashSet;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::core::{ClassHash, EthAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{EventContent, L2ToL1Payload};

use crate::execution::entry_point::CallEntryPoint;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionResult;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Retdata(pub Vec<StarkFelt>);

#[macro_export]
macro_rules! retdata {
    ( $( $x:expr ),* ) => {
        Retdata(vec![$($x),*])
    };
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct OrderedEvent {
    pub order: usize,
    pub event: EventContent,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct MessageToL1 {
    pub to_address: EthAddress,
    pub payload: L2ToL1Payload,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct OrderedL2ToL1Message {
    pub order: usize,
    pub message: MessageToL1,
}

/// Represents the effects of executing a single entry point.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallExecution {
    pub retdata: Retdata,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub failed: bool,
    pub gas_consumed: u64,
}

/// Represents the full effects of executing an entry point, including the inner calls it invoked.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallInfo {
    pub call: CallEntryPoint,
    pub execution: CallExecution,
    pub vm_resources: VmExecutionResources,
    pub inner_calls: Vec<CallInfo>,

    // Additional information gathered during execution.
    pub storage_read_values: Vec<StarkFelt>,
    pub accessed_storage_keys: HashSet<StorageKey>,
}

impl CallInfo {
    /// Returns the set of class hashes that were executed during this call execution.
    // TODO: Add unit test for this method
    pub fn get_executed_class_hashes(&self) -> HashSet<ClassHash> {
        let mut class_hashes = HashSet::new();
        let calls = self.into_iter();
        for call in calls {
            class_hashes
                .insert(call.call.class_hash.expect("Class hash must be set after execution."));
        }

        class_hashes
    }

    /// Returns a list of StarkNet L2ToL1Payload length collected during the execution, sorted
    /// by the order in which they were sent.
    pub fn get_sorted_l2_to_l1_payloads_length(&self) -> TransactionExecutionResult<Vec<usize>> {
        let n_messages = self.into_iter().map(|call| call.execution.l2_to_l1_messages.len()).sum();
        let mut starknet_l2_to_l1_payloads_length: Vec<Option<usize>> = vec![None; n_messages];

        for call in self.into_iter() {
            for ordered_message_content in &call.execution.l2_to_l1_messages {
                let message_order = ordered_message_content.order;
                if message_order >= n_messages {
                    return Err(TransactionExecutionError::InvalidOrder {
                        object: "L2-to-L1 message".to_string(),
                        order: message_order,
                        max_order: n_messages,
                    });
                }
                starknet_l2_to_l1_payloads_length[message_order] =
                    Some(ordered_message_content.message.payload.0.len());
            }
        }

        starknet_l2_to_l1_payloads_length.into_iter().enumerate().try_fold(
            Vec::new(),
            |mut acc, (i, option)| match option {
                Some(value) => {
                    acc.push(value);
                    Ok(acc)
                }
                None => Err(TransactionExecutionError::UnexpectedHoles {
                    object: "L2-to-L1 message".to_string(),
                    order: i,
                }),
            },
        )
    }
}

pub struct CallInfoIter<'a> {
    call_infos: Vec<&'a CallInfo>,
}

impl<'a> Iterator for CallInfoIter<'a> {
    type Item = &'a CallInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(call_info) = self.call_infos.pop() else {
            return None;
        };

        // Push order is right to left.
        self.call_infos.extend(call_info.inner_calls.iter().rev());
        Some(call_info)
    }
}

impl<'a> IntoIterator for &'a CallInfo {
    type Item = &'a CallInfo;
    type IntoIter = CallInfoIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        CallInfoIter { call_infos: vec![self] }
    }
}
