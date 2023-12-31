use core::panic;
use std::collections::{HashMap, HashSet};

use blockifier::execution::call_info::{CallInfo, OrderedEvent, OrderedL2ToL1Message};
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use num_bigint::BigUint;
use pyo3::prelude::*;
use serde::Serialize;

use crate::py_utils::{to_py_vec, PyFelt};

#[pyclass]
#[derive(Clone)]
pub struct PyTransactionExecutionInfo {
    #[pyo3(get)]
    pub validate_call_info: Option<PyCallInfo>,
    #[pyo3(get)]
    pub execute_call_info: Option<PyCallInfo>,
    #[pyo3(get)]
    pub fee_transfer_call_info: Option<PyCallInfo>,
    #[pyo3(get)]
    pub actual_fee: u128,
    #[pyo3(get)]
    pub actual_resources: HashMap<String, usize>,
    #[pyo3(get)]
    pub revert_error: Option<String>,
}

pub trait ToBytesString {
    fn to_bytes_string(&self, tx_type: &str) -> String;
}

// TODO(Mohammad, 20/1/2024): Check if it can be implemented in a better way.
impl ToBytesString for PyTransactionExecutionInfo {
    fn to_bytes_string(&self, tx_type: &str) -> String {
        let validate_call_info_str = match &self.validate_call_info {
            Some(info) => format!("\"validate_info\": {}", info.to_bytes_string(tx_type)),
            None => String::from("\"validate_info\": null"),
        };

        let execute_call_info_str = match &self.execute_call_info {
            Some(info) => format!("\"call_info\": {}", info.to_bytes_string(tx_type)),
            None => String::from("\"call_info\": null"),
        };

        let fee_transfer_call_info_str = match &self.fee_transfer_call_info {
            Some(info) => format!("\"fee_transfer_info\": {}", info.to_bytes_string(tx_type)),
            None => String::from("\"fee_transfer_info\": null"),
        };

        let actual_fee_str = format!("\"actual_fee\": \"0x{:x}\"", self.actual_fee);

        let actual_resources_str = format!(
            "\"actual_resources\": {}",
            serde_json::to_string(&self.actual_resources).unwrap()
        );

        let tx_type_str = format!("\"tx_type\": \"{}\"", tx_type);

        let revert_error_str = match &self.revert_error {
            Some(error) => {
                format!(
                    "\"revert_error\": \"{}\"",
                    error.replace('\n', "\\n").replace('\"', "\\\"")
                )
            }
            None => String::from("\"revert_error\": null"),
        };

        let result_str = format!(
            "{{{}, {}, {}, {}, {}, {}, {}}}",
            validate_call_info_str,
            execute_call_info_str,
            fee_transfer_call_info_str,
            actual_fee_str,
            actual_resources_str,
            tx_type_str,
            revert_error_str
        );

        result_str
    }
}

impl From<TransactionExecutionInfo> for PyTransactionExecutionInfo {
    // TODO(Gilad, 1/4/2023): Check that everything can't fail, recursively.
    fn from(info: TransactionExecutionInfo) -> Self {
        Self {
            validate_call_info: info.validate_call_info.map(PyCallInfo::from),
            execute_call_info: info.execute_call_info.map(PyCallInfo::from),
            fee_transfer_call_info: info.fee_transfer_call_info.map(PyCallInfo::from),
            actual_fee: info.actual_fee.0,
            actual_resources: info.actual_resources.0,
            revert_error: info.revert_error,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyCallInfo {
    // Call params.
    #[pyo3(get)]
    pub caller_address: PyFelt,
    #[pyo3(get)]
    pub contract_address: PyFelt,
    #[pyo3(get)]
    pub class_hash: Option<PyFelt>,
    #[pyo3(get)]
    pub entry_point_selector: PyFelt,
    #[pyo3(get)]
    pub entry_point_type: u8,
    #[pyo3(get)]
    pub calldata: Vec<PyFelt>,
    #[pyo3(get)]
    pub call_type: u8,

    // Call results.
    #[pyo3(get)]
    pub gas_consumed: u64, // Currently not in use.
    #[pyo3(get)]
    pub failure_flag: PyFelt, // Currently not in use.
    #[pyo3(get)]
    pub retdata: Vec<PyFelt>,
    #[pyo3(get)]
    pub execution_resources: PyVmExecutionResources,
    #[pyo3(get)]
    pub events: Vec<PyOrderedEvent>,
    #[pyo3(get)]
    pub l2_to_l1_messages: Vec<PyOrderedL2ToL1Message>,

    // Internal calls invoked by this call.
    #[pyo3(get)]
    pub internal_calls: Vec<PyCallInfo>,

    // Information kept for following flows (fee, OS).
    #[pyo3(get)]
    pub storage_read_values: Vec<PyFelt>,
    #[pyo3(get)]
    pub accessed_storage_keys: HashSet<PyFelt>,

    // Deprecated fields; maintained for backward compatibility to Python.
    #[pyo3(get)]
    pub code_address: Option<PyFelt>,
}

// TODO(Mohammad, 20/1/2024): Check if it can be implemented in a better way.
impl ToBytesString for PyCallInfo {
    fn to_bytes_string(&self, _tx_type: &str) -> String {
        let caller_address_str = format!(
            "\"caller_address\": {}",
            BigUint::from_bytes_be(self.caller_address.0.bytes())
        );
        let call_type_str = match self.call_type {
            0 => "\"call_type\": \"CALL\"",
            1 => "\"call_type\": \"DELEGATE\"",
            _ => panic!("Invalid call type"),
        };

        let contract_address_str = format!(
            "\"contract_address\": {}",
            BigUint::from_bytes_be(self.contract_address.0.bytes())
        );
        let class_hash_str = match &self.class_hash {
            Some(hash) => {
                format!("\"class_hash\": \"0x{:x}\"", BigUint::from_bytes_be(hash.0.bytes()))
            }
            None => String::from("\"class_hash\": null"),
        };
        let entry_point_selector_str = format!(
            "\"entry_point_selector\": {}",
            BigUint::from_bytes_be(self.entry_point_selector.0.bytes())
        );

        let entry_point_type_str = match self.entry_point_type {
            0 => "\"entry_point_type\": \"CONSTRUCTOR\"",
            1 => "\"entry_point_type\": \"EXTERNAL\"",
            2 => "\"entry_point_type\": \"L1_HANDLER\"",
            _ => panic!("Invalid entry point type"),
        };
        let calldata_str = format!(
            "\"calldata\": [{}]",
            &self
                .calldata
                .iter()
                .map(|item| format!("{}", BigUint::from_bytes_be(item.0.bytes())))
                .collect::<Vec<_>>()
                .join(", ")
        );
        // };

        let gas_consumed_str = format!("\"gas_consumed\": \"0x{:x}\"", self.gas_consumed);
        let failure_flag_str = format!(
            "\"failure_flag\": \"0x{:x}\"",
            BigUint::from_bytes_be(self.failure_flag.0.bytes())
        );
        let retdata_str = format!(
            "\"retdata\": [{}]",
            &self
                .retdata
                .iter()
                .map(|item| format!("{}", BigUint::from_bytes_be(item.0.bytes())))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let execution_resources_str = format!(
            "\"execution_resources\": {}",
            self.execution_resources.to_bytes_string(_tx_type)
        );

        let events_str = if self.events.is_empty() {
            "\"events\": []".to_string()
        } else {
            format!(
                "\"events\": [{}]",
                self.events
                    .iter()
                    .map(|item| item.to_bytes_string(_tx_type))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        let l2_to_l1_messages_str = if self.l2_to_l1_messages.is_empty() {
            "\"l2_to_l1_messages\": []".to_string()
        } else {
            format!(
                "\"l2_to_l1_messages\": [{}]",
                self.l2_to_l1_messages
                    .iter()
                    .map(|item| item.to_bytes_string(_tx_type))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        let storage_read_values_str = format!(
            "\"storage_read_values\": [{}]",
            &self
                .storage_read_values
                .iter()
                .map(|item| format!("{}", BigUint::from_bytes_be(item.0.bytes())))
                .collect::<Vec<_>>()
                .join(", ")
        );

        let accessed_storage_keys_str = format!(
            "\"accessed_storage_keys\": [{}]",
            self.accessed_storage_keys
                .iter()
                .map(|item| format!("\"0x{:x}\"", BigUint::from_bytes_be(item.0.bytes())))
                .collect::<Vec<_>>()
                .join(", "),
        );
        let internal_calls_str = if self.internal_calls.is_empty() {
            "\"internal_calls\": []".to_string()
        } else {
            format!(
                "\"internal_calls\": [{}]",
                self.internal_calls
                    .iter()
                    .map(|item| item.to_bytes_string(_tx_type))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        };

        let code_address_str = match &self.code_address {
            Some(code_address) => {
                format!("\"code_address\": {}", BigUint::from_bytes_be(code_address.0.bytes()))
            }
            None => String::from("\"code_address\": null"),
        };

        let result_str = format!(
            "{{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}",
            caller_address_str,
            call_type_str,
            contract_address_str,
            class_hash_str,
            entry_point_selector_str,
            entry_point_type_str,
            calldata_str,
            gas_consumed_str,
            failure_flag_str,
            retdata_str,
            execution_resources_str,
            events_str,
            l2_to_l1_messages_str,
            storage_read_values_str,
            accessed_storage_keys_str,
            internal_calls_str,
            code_address_str
        );

        result_str
    }
}

impl From<CallInfo> for PyCallInfo {
    fn from(call_info: CallInfo) -> Self {
        let call = call_info.call;
        let execution = call_info.execution;

        Self {
            caller_address: PyFelt::from(call.caller_address),
            contract_address: PyFelt::from(call.storage_address),
            class_hash: call.class_hash.map(PyFelt::from),
            entry_point_selector: PyFelt(call.entry_point_selector.0),
            entry_point_type: call.entry_point_type as u8,
            calldata: to_py_vec(call.calldata.0.to_vec(), PyFelt),
            gas_consumed: execution.gas_consumed,
            failure_flag: PyFelt::from(execution.failed as u8),
            retdata: to_py_vec(execution.retdata.0, PyFelt),
            execution_resources: PyVmExecutionResources::from(call_info.vm_resources),
            events: to_py_vec(execution.events, PyOrderedEvent::from),
            l2_to_l1_messages: to_py_vec(execution.l2_to_l1_messages, PyOrderedL2ToL1Message::from),
            internal_calls: to_py_vec(call_info.inner_calls, PyCallInfo::from),
            storage_read_values: to_py_vec(call_info.storage_read_values, PyFelt),
            accessed_storage_keys: call_info
                .accessed_storage_keys
                .into_iter()
                .map(|storage_key| PyFelt(*storage_key.0.key()))
                .collect(),
            call_type: call.call_type as u8,
            code_address: call.code_address.map(PyFelt::from),
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyOrderedEvent {
    #[pyo3(get)]
    pub order: usize,
    #[pyo3(get)]
    pub keys: Vec<PyFelt>,
    #[pyo3(get)]
    pub data: Vec<PyFelt>,
}

// TODO(Mohammad, 20/1/2024): Check if it can be implemented in a better way.
impl ToBytesString for PyOrderedEvent {
    fn to_bytes_string(&self, _tx_type: &str) -> String {
        let order_str = format!("\"order\": {}", self.order);
        let keys_str = format!(
            "\"keys\": [{}]",
            self.keys
                .iter()
                .map(|item| format!("\"0x{:x}\"", BigUint::from_bytes_be(item.0.bytes())))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let data_str = format!(
            "\"data\": [{}]",
            self.data
                .iter()
                .map(|item| format!("\"0x{:x}\"", BigUint::from_bytes_be(item.0.bytes())))
                .collect::<Vec<_>>()
                .join(", "),
        );
        let result_str = format!("{{{}, {}, {}}}", order_str, keys_str, data_str);

        result_str
    }
}

impl From<OrderedEvent> for PyOrderedEvent {
    fn from(ordered_event: OrderedEvent) -> Self {
        let keys = to_py_vec(ordered_event.event.keys, |x| PyFelt(x.0));
        let data = to_py_vec(ordered_event.event.data.0, PyFelt);
        Self { order: ordered_event.order, keys, data }
    }
}

#[pyclass]
#[derive(Clone, Debug, Serialize)]
pub struct PyOrderedL2ToL1Message {
    #[pyo3(get)]
    pub order: usize,
    #[pyo3(get)]
    pub to_address: PyFelt,
    #[pyo3(get)]
    pub payload: Vec<PyFelt>,
}

impl ToBytesString for PyOrderedL2ToL1Message {
    fn to_bytes_string(&self, _tx_type: &str) -> String {
        let order_str = format!("\"order\": {}", self.order);
        let to_address_str =
            format!("\"to_address\": {}", BigUint::from_bytes_be(self.to_address.0.bytes()));
        let payload_str = format!(
            "\"payload\": [{}]",
            self.payload
                .iter()
                .map(|item| format!("\"0x{:x}\"", BigUint::from_bytes_be(item.0.bytes())))
                .collect::<Vec<_>>()
                .join(", "),
        );

        let result_str = format!("{{{}, {}, {}}}", order_str, to_address_str, payload_str);

        result_str
    }
}

impl From<OrderedL2ToL1Message> for PyOrderedL2ToL1Message {
    fn from(ordered_message: OrderedL2ToL1Message) -> Self {
        let payload = to_py_vec(ordered_message.message.payload.0, PyFelt);
        Self {
            order: ordered_message.order,
            to_address: PyFelt::from(ordered_message.message.to_address),
            payload,
        }
    }
}

#[pyclass]
#[derive(Clone, Default, Debug)]
pub struct PyVmExecutionResources {
    #[pyo3(get)]
    pub n_steps: usize,
    #[pyo3(get)]
    pub builtin_instance_counter: HashMap<String, usize>,
    #[pyo3(get)]
    pub n_memory_holes: usize,
}

impl ToBytesString for PyVmExecutionResources {
    fn to_bytes_string(&self, _tx_type: &str) -> String {
        let n_steps_str = format!("\"n_steps\": {}", self.n_steps);
        let builtin_instance_counter_str = if self.builtin_instance_counter.is_empty() {
            "\"builtin_instance_counter\": {}".to_string()
        } else {
            format!(
                "\"builtin_instance_counter\": {{{}}}",
                self.builtin_instance_counter
                    .iter()
                    .map(|(key, value)| format!("\"{}\": {}", key, value))
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        };

        let n_memory_holes_str = format!("\"n_memory_holes\": {}", self.n_memory_holes);

        let result_str = format!(
            "{{{}, {}, {}}}",
            n_steps_str, builtin_instance_counter_str, n_memory_holes_str
        );

        result_str
    }
}

impl From<VmExecutionResources> for PyVmExecutionResources {
    fn from(vm_resources: VmExecutionResources) -> Self {
        Self {
            n_steps: vm_resources.n_steps,
            builtin_instance_counter: vm_resources.builtin_instance_counter,
            n_memory_holes: vm_resources.n_memory_holes,
        }
    }
}

#[pyclass]
#[derive(Clone, Default)]
pub struct PyBouncerInfo {
    #[pyo3(get)]
    // The number of felts needed to store L1<>L2 messages.
    pub messages_size: usize,
    #[pyo3(get)]
    pub additional_os_resources: PyVmExecutionResources,
}
