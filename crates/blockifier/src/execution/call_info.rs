use std::collections::HashSet;
use std::iter::Sum;
use std::ops::Add;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde::Serialize;
use starknet_api::core::{ClassHash, ContractAddress, EthAddress, PatriciaKey};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{EventContent, L2ToL1Payload};
use starknet_api::{felt, patricia_key};
use starknet_types_core::felt::Felt;

use crate::execution::entry_point::CallEntryPoint;
use crate::fee::gas_usage::get_message_segment_length;
use crate::state::cached_state::StorageEntry;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Retdata(pub Vec<Felt>);

#[macro_export]
macro_rules! retdata {
    ( $( $x:expr ),* ) => {
        Retdata(vec![$($x),*])
    };
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct OrderedEvent {
    pub order: usize,
    pub event: EventContent,
}

#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct MessageL1CostInfo {
    pub l2_to_l1_payload_lengths: Vec<usize>,
    pub message_segment_length: usize,
}

impl MessageL1CostInfo {
    pub fn calculate<'a>(
        call_infos: impl Iterator<Item = &'a CallInfo>,
        l1_handler_payload_size: Option<usize>,
    ) -> Self {
        let mut l2_to_l1_payload_lengths = Vec::new();
        for call_info in call_infos {
            l2_to_l1_payload_lengths.extend(call_info.get_l2_to_l1_payload_lengths());
        }

        let message_segment_length =
            get_message_segment_length(&l2_to_l1_payload_lengths, l1_handler_payload_size);

        Self { l2_to_l1_payload_lengths, message_segment_length }
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Clone)]
pub struct MessageToL1 {
    pub to_address: EthAddress,
    pub payload: L2ToL1Payload,
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Clone)]
pub struct OrderedL2ToL1Message {
    pub order: usize,
    pub message: MessageToL1,
}

pub fn get_payload_lengths(l2_to_l1_messages: &[OrderedL2ToL1Message]) -> Vec<usize> {
    l2_to_l1_messages.iter().map(|message| message.message.payload.0.len()).collect()
}

/// Represents the effects of executing a single entry point.
#[derive(Debug, Default, Eq, PartialEq, Serialize, Clone)]
pub struct CallExecution {
    pub retdata: Retdata,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub failed: bool,
    pub gas_consumed: u64,
}

#[derive(Default)]
pub struct ExecutionSummary {
    pub executed_class_hashes: HashSet<ClassHash>,
    pub visited_storage_entries: HashSet<StorageEntry>,
    pub l2_to_l1_payload_lengths: Vec<usize>,
    pub n_events: usize,
}

impl Add for ExecutionSummary {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self.executed_class_hashes.extend(other.executed_class_hashes);
        self.visited_storage_entries.extend(other.visited_storage_entries);
        self.l2_to_l1_payload_lengths.extend(other.l2_to_l1_payload_lengths);
        self.n_events += other.n_events;
        self
    }
}

impl Sum for ExecutionSummary {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ExecutionSummary::default(), |acc, x| acc + x)
    }
}

#[derive(Debug, Default)]
pub struct TestExecutionSummary {
    pub num_of_events: usize,
    pub num_of_messages: usize,
    pub class_hash: ClassHash,
    pub storage_address: ContractAddress,
    pub storage_key: StorageKey,
}

impl TestExecutionSummary {
    pub fn new(
        num_of_events: usize,
        num_of_messages: usize,
        class_hash: ClassHash,
        storage_address: &str,
        storage_key: &str,
    ) -> Self {
        TestExecutionSummary {
            num_of_events,
            num_of_messages,
            class_hash,
            storage_address: ContractAddress(patricia_key!(storage_address)),
            storage_key: StorageKey(patricia_key!(storage_key)),
        }
    }

    pub fn to_call_info(&self) -> CallInfo {
        CallInfo {
            call: CallEntryPoint {
                class_hash: Some(self.class_hash),
                storage_address: self.storage_address,
                ..Default::default()
            },
            execution: CallExecution {
                events: (0..self.num_of_events).map(|_| OrderedEvent::default()).collect(),
                l2_to_l1_messages: (0..self.num_of_messages)
                    .map(|i| OrderedL2ToL1Message {
                        order: i,
                        message: MessageToL1 {
                            to_address: EthAddress::default(),
                            payload: L2ToL1Payload(vec![Felt::default()]),
                        },
                    })
                    .collect(),
                ..Default::default()
            },
            accessed_storage_keys: vec![self.storage_key].into_iter().collect(),
            ..Default::default()
        }
    }
}

/// Represents the full effects of executing an entry point, including the inner calls it invoked.
#[derive(Debug, Default, Eq, PartialEq, Serialize, Clone)]
pub struct CallInfo {
    pub call: CallEntryPoint,
    pub execution: CallExecution,
    pub resources: ExecutionResources,
    pub inner_calls: Vec<CallInfo>,

    // Additional information gathered during execution.
    pub storage_read_values: Vec<Felt>,
    pub accessed_storage_keys: HashSet<StorageKey>,
}

impl CallInfo {
    pub fn iter(&self) -> CallInfoIter<'_> {
        let call_infos = vec![self];
        CallInfoIter { call_infos }
    }

    pub fn get_l2_to_l1_payload_lengths(&self) -> Vec<usize> {
        self.iter().fold(Vec::new(), |mut acc, call_info| {
            acc.extend(get_payload_lengths(&call_info.execution.l2_to_l1_messages));
            acc
        })
    }

    pub fn summarize(&self) -> ExecutionSummary {
        let mut executed_class_hashes: HashSet<ClassHash> = HashSet::new();
        let mut visited_storage_entries: HashSet<StorageEntry> = HashSet::new();
        let mut n_events: usize = 0;
        let mut l2_to_l1_payload_lengths = Vec::new();

        for call_info in self.iter() {
            let class_hash =
                call_info.call.class_hash.expect("Class hash must be set after execution.");
            executed_class_hashes.insert(class_hash);

            let call_storage_entries = call_info
                .accessed_storage_keys
                .iter()
                .map(|storage_key| (call_info.call.storage_address, *storage_key));
            visited_storage_entries.extend(call_storage_entries);

            n_events += call_info.execution.events.len();

            l2_to_l1_payload_lengths
                .extend(get_payload_lengths(&call_info.execution.l2_to_l1_messages));
        }

        ExecutionSummary {
            executed_class_hashes,
            visited_storage_entries,
            l2_to_l1_payload_lengths,
            n_events,
        }
    }
}

pub struct CallInfoIter<'a> {
    call_infos: Vec<&'a CallInfo>,
}

impl<'a> Iterator for CallInfoIter<'a> {
    type Item = &'a CallInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let call_info = self.call_infos.pop()?;

        // Push order is right to left.
        self.call_infos.extend(call_info.inner_calls.iter().rev());
        Some(call_info)
    }
}
