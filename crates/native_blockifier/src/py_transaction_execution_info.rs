use std::collections::{HashMap, HashSet};

use blockifier::execution::entry_point::{CallInfo, OrderedEvent, OrderedL2ToL1Message};
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pyo3::prelude::*;

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
#[derive(Clone)]
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
    pub gas_consumed: PyFelt, // Currently not in use.
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
            gas_consumed: PyFelt(execution.gas_consumed),
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
#[derive(Clone)]
pub struct PyOrderedEvent {
    #[pyo3(get)]
    pub order: usize,
    #[pyo3(get)]
    pub keys: Vec<PyFelt>,
    #[pyo3(get)]
    pub data: Vec<PyFelt>,
}

impl From<OrderedEvent> for PyOrderedEvent {
    fn from(ordered_event: OrderedEvent) -> Self {
        let keys = to_py_vec(ordered_event.event.keys, |x| PyFelt(x.0));
        let data = to_py_vec(ordered_event.event.data.0, PyFelt);
        Self { order: ordered_event.order, keys, data }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyOrderedL2ToL1Message {
    #[pyo3(get)]
    pub order: usize,
    #[pyo3(get)]
    pub to_address: PyFelt,
    #[pyo3(get)]
    pub payload: Vec<PyFelt>,
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
#[derive(Clone, Default)]
pub struct PyVmExecutionResources {
    #[pyo3(get)]
    pub n_steps: usize,
    #[pyo3(get)]
    pub builtin_instance_counter: HashMap<String, usize>,
    #[pyo3(get)]
    pub n_memory_holes: usize,
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
