use std::collections::{HashMap, HashSet};

use blockifier::execution::entry_point::CallInfo;
use blockifier::transaction::objects::TransactionExecutionInfo;
use pyo3::prelude::*;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{EventContent, MessageToL1};

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
    pub caller_address: PyFelt,
    pub contract_address: PyFelt,
    pub class_hash: Option<PyFelt>,
    pub entry_point_selector: PyFelt,
    pub entry_point_type: usize,
    pub calldata: Vec<PyFelt>,

    // Call results.
    pub gas_consumed: PyFelt, // Currently not in use.
    pub failure_flag: PyFelt, // Currently not in use.
    pub retdata: Vec<PyFelt>,
    pub execution_resources: PyExecutionResources,
    pub events: Vec<PyEvent>,
    pub l2_to_l1_messages: Vec<PyL2ToL1Message>,

    // Internal calls invoked by this call.
    pub internal_calls: Vec<PyCallInfo>,

    // Information kept for following flows (fee, OS).
    pub storage_read_values: Vec<PyFelt>,
    pub accessed_storage_keys: HashSet<PyFelt>,

    // Deprecated fields; maintained for backward compatibility to Python.
    pub call_type: usize,
    pub code_address: Option<PyFelt>,
}

impl From<CallInfo> for PyCallInfo {
    fn from(call_info: CallInfo) -> Self {
        let call = call_info.call;
        let execution = call_info.execution;

        Self {
            caller_address: PyFelt::from(call.caller_address),
            call_type: 0, // CallType::CALL.
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
            storage_read_values: vec![],
            accessed_storage_keys: HashSet::new(),
            internal_calls: call_info.inner_calls.into_iter().map(PyCallInfo::from).collect(),
            code_address: None,
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyEvent {
    pub keys: Vec<PyFelt>,
    pub data: Vec<PyFelt>,
}

impl From<EventContent> for PyEvent {
    fn from(events: EventContent) -> Self {
        let keys = events.keys.into_iter().map(|x| PyFelt(x.0)).collect();
        let data = starkfelt_to_pyfelt_vec(events.data.0);
        Self { keys, data }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyL2ToL1Message {
    pub to_address: PyFelt,
    pub payload: Vec<PyFelt>,
}

impl From<MessageToL1> for PyL2ToL1Message {
    fn from(message: MessageToL1) -> Self {
        let payload = starkfelt_to_pyfelt_vec(message.payload.0);
        Self { to_address: PyFelt::from(message.to_address), payload }
    }
}

#[pyclass]
#[derive(Clone, Default)]
pub struct PyExecutionResources {
    pub n_steps: usize,
    pub builtin_instance_counter: HashMap<String, usize>,
    pub n_memory_holes: usize,
}
