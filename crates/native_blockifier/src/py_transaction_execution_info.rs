use std::collections::{HashMap, HashSet};

use blockifier::execution::entry_point::{CallInfo, OrderedEvent, OrderedL2ToL1Message};
use blockifier::transaction::objects::TransactionExecutionInfo;
use pyo3::prelude::*;
use starknet_api::hash::StarkFelt;

use crate::py_utils::{starkfelt_to_pyfelt_vec, PyFelt};

#[pyclass]
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
}

impl From<TransactionExecutionInfo> for PyTransactionExecutionInfo {
    fn from(info: TransactionExecutionInfo) -> Self {
        Self {
            validate_call_info: info.validate_call_info.map(PyCallInfo::from),
            execute_call_info: info.execute_call_info.map(PyCallInfo::from),
            fee_transfer_call_info: info.fee_transfer_call_info.map(PyCallInfo::from),
            actual_fee: info.actual_fee.0,
            actual_resources: info.actual_resources.0,
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
    pub entry_point_type: usize,
    #[pyo3(get)]
    pub calldata: Vec<PyFelt>,

    // Call results.
    #[pyo3(get)]
    pub gas_consumed: PyFelt, // Currently not in use.
    #[pyo3(get)]
    pub failure_flag: PyFelt, // Currently not in use.
    #[pyo3(get)]
    pub retdata: Vec<PyFelt>,
    #[pyo3(get)]
    pub execution_resources: PyExecutionResources,
    #[pyo3(get)]
    pub events: Vec<PyEvent>,
    #[pyo3(get)]
    pub l2_to_l1_messages: Vec<PyL2ToL1Message>,

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
    pub call_type: usize,
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
            class_hash: call.class_hash.map(|class_hash| PyFelt(class_hash.0)),
            entry_point_selector: PyFelt(call.entry_point_selector.0),
            entry_point_type: call.entry_point_type as usize,
            calldata: starkfelt_to_pyfelt_vec(call.calldata.0.to_vec()),
            gas_consumed: PyFelt(StarkFelt::default()),
            failure_flag: PyFelt(StarkFelt::default()),
            retdata: starkfelt_to_pyfelt_vec(execution.retdata.0),
            // TODO(Elin, 01/03/2023): Initialize correctly.
            execution_resources: PyExecutionResources::default(),
            events: execution.events.into_iter().map(PyEvent::from).collect(),
            l2_to_l1_messages: execution
                .l2_to_l1_messages
                .into_iter()
                .map(PyL2ToL1Message::from)
                .collect(),
            internal_calls: call_info.inner_calls.into_iter().map(PyCallInfo::from).collect(),
            storage_read_values: vec![],
            accessed_storage_keys: HashSet::new(),
            call_type: 0, // CallType::CALL.
            code_address: None,
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyEvent {
    #[pyo3(get)]
    pub order: usize,
    #[pyo3(get)]
    pub keys: Vec<PyFelt>,
    #[pyo3(get)]
    pub data: Vec<PyFelt>,
}

impl From<OrderedEvent> for PyEvent {
    fn from(event: OrderedEvent) -> Self {
        let keys = event.content.keys.into_iter().map(|x| PyFelt(x.0)).collect();
        let data = starkfelt_to_pyfelt_vec(event.content.data.0);
        Self { order: event.order, keys, data }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyL2ToL1Message {
    #[pyo3(get)]
    pub order: usize,
    #[pyo3(get)]
    pub to_address: PyFelt,
    #[pyo3(get)]
    pub payload: Vec<PyFelt>,
}

impl From<OrderedL2ToL1Message> for PyL2ToL1Message {
    fn from(message: OrderedL2ToL1Message) -> Self {
        let payload = starkfelt_to_pyfelt_vec(message.content.payload.0);
        Self { order: message.order, to_address: PyFelt::from(message.content.to_address), payload }
    }
}

#[pyclass]
#[derive(Clone, Default)]
pub struct PyExecutionResources {
    #[pyo3(get)]
    pub n_steps: usize,
    #[pyo3(get)]
    pub builtin_instance_counter: HashMap<String, usize>,
    #[pyo3(get)]
    pub n_memory_holes: usize,
}
