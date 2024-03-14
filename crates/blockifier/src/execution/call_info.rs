use std::collections::{HashMap, HashSet};
use std::iter::Sum;
use std::ops::Add;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use serde::{Deserialize, Serialize};
use starknet_api::core::{ClassHash, ContractAddress, EthAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::patricia_key;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{EventContent, L2ToL1Payload};

use crate::execution::entry_point::CallEntryPoint;
use crate::fee::gas_usage::get_message_segment_length;
use crate::state::cached_state::StorageEntry;
use crate::transaction::objects::TransactionExecutionResult;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Retdata(pub Vec<StarkFelt>);

#[macro_export]
macro_rules! retdata {
    ( $( $x:expr ),* ) => {
        Retdata(vec![$($x),*])
    };
}

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
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
    ) -> TransactionExecutionResult<Self> {
        let mut l2_to_l1_payload_lengths = Vec::new();
        for call_info in call_infos {
            println!("yael old calculate enter new call info");
            l2_to_l1_payload_lengths
                .extend(call_info.get_recursive_call_info_l2_to_l1_payload_lengths());
            println!("yael old calculate l2_to_l1_payload_lengths: {:?}", l2_to_l1_payload_lengths);
        }

        let message_segment_length =
            get_message_segment_length(&l2_to_l1_payload_lengths, l1_handler_payload_size);

        Ok(Self { l2_to_l1_payload_lengths, message_segment_length })
    }
}

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct MessageToL1 {
    pub to_address: EthAddress,
    pub payload: L2ToL1Payload,
}

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct OrderedL2ToL1Message {
    pub order: usize,
    pub message: MessageToL1,
}

/// Represents the effects of executing a single entry point.
#[cfg_attr(test, derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct CallExecution {
    pub retdata: Retdata,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub failed: bool,
    pub gas_consumed: u64,
}

// This struct is used to implement `serde` functionality in a remote `ExecutionResources` Struct.
#[derive(Debug, Default, Deserialize, derive_more::From, Eq, PartialEq, Serialize)]
#[serde(remote = "ExecutionResources")]
struct ExecutionResourcesDef {
    n_steps: usize,
    n_memory_holes: usize,
    builtin_instance_counter: HashMap<String, usize>,
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
    pub class_hash: ClassHash,
    pub storage_address: ContractAddress,
    pub storage_key: StorageKey,
}

impl TestExecutionSummary {
    pub fn new(
        num_of_events: usize,
        class_hash: ClassHash,
        storage_address: &str,
        storage_key: &str,
    ) -> Self {
        TestExecutionSummary {
            num_of_events,
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
                ..Default::default()
            },
            accessed_storage_keys: vec![self.storage_key].into_iter().collect(),
            ..Default::default()
        }
    }
}

/// Represents the full effects of executing an entry point, including the inner calls it invoked.
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct CallInfo {
    pub call: CallEntryPoint,
    pub execution: CallExecution,
    #[serde(with = "ExecutionResourcesDef")]
    pub resources: ExecutionResources,
    pub inner_calls: Vec<CallInfo>,

    // Additional information gathered during execution.
    pub storage_read_values: Vec<StarkFelt>,
    pub accessed_storage_keys: HashSet<StorageKey>,
}

impl CallInfo {
    pub fn iter(&self) -> CallInfoIter<'_> {
        let call_infos = vec![self];
        CallInfoIter { call_infos }
    }

    pub fn get_call_info_l2_to_l1_payload_lengths(&self) -> Vec<usize> {
        self.execution
            .l2_to_l1_messages
            .iter()
            .map(|message| message.message.payload.0.len())
            .collect()
    }

    pub fn get_sorted_l2_to_l1_payload_lengths(&self) -> Vec<usize> {
        let n_messages = self.iter().map(|call| call.execution.l2_to_l1_messages.len()).sum();
        let mut starknet_l2_to_l1_payload_lengths: Vec<Option<usize>> = vec![None; n_messages];

        for call_info in self.iter() {
            for ordered_message_content in &call_info.execution.l2_to_l1_messages {
                let message_order = ordered_message_content.order;
                if message_order >= n_messages {
                    panic!(
                        "L2 to L1 message order is out of bounds. order {} > n_messages {}.",
                        message_order, n_messages
                    );
                }
                starknet_l2_to_l1_payload_lengths[message_order] =
                    Some(ordered_message_content.message.payload.0.len());
            }
        }

        starknet_l2_to_l1_payload_lengths.into_iter().enumerate().fold(
            Vec::new(),
            |mut acc, (i, option)| match option {
                Some(value) => {
                    acc.push(value);
                    acc
                }
                None => panic!("L2 to L1 messages order has an unexpected hole in order = {}.", i),
            },
        )
    }

    pub fn get_recursive_call_info_l2_to_l1_payload_lengths(&self) -> Vec<usize> {
        let mut l2_to_l1_lengths = Vec::new();
        for call_info in self.iter() {
            l2_to_l1_lengths.extend(call_info.get_call_info_l2_to_l1_payload_lengths());
        }
        l2_to_l1_lengths
    }

    pub fn summarize(&self) -> ExecutionSummary {
        let mut executed_class_hashes: HashSet<ClassHash> = HashSet::new();
        let mut visited_storage_entries: HashSet<StorageEntry> = HashSet::new();
        let mut n_events: usize = 0;
        let mut l2_to_l1_payload_lengths = Vec::new();
        println!("yael new calculate enter new call info");

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

            l2_to_l1_payload_lengths.extend(call_info.get_call_info_l2_to_l1_payload_lengths());
            println!("yael new summarize l2_to_l1_payload_lengths: {:?}", l2_to_l1_payload_lengths);
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
        let Some(call_info) = self.call_infos.pop() else {
            return None;
        };

        // Push order is right to left.
        self.call_infos.extend(call_info.inner_calls.iter().rev());
        Some(call_info)
    }
}
