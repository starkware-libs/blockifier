use std::collections::HashMap;

use blockifier::execution::entry_point::CallInfo;
use blockifier::transaction::objects::TransactionExecutionInfo;
use pyo3::prelude::*;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{EventContent, MessageToL1};

use crate::py_utils::PyFelt;

#[pyclass]
pub struct PyTransactionExecutionInfo {
    pub validate_call_info: Option<PyCallInfo>,
    pub execute_call_info: Option<PyCallInfo>,
    pub fee_transfer_call_info: Option<PyCallInfo>,
    #[pyo3(get)]
    pub actual_fee: u128,
    #[pyo3(get)]
    pub actual_resources: HashMap<String, usize>,
}

impl From<TransactionExecutionInfo> for PyTransactionExecutionInfo {
    fn from(tx_execution_info: TransactionExecutionInfo) -> Self {
        Self {
            validate_call_info: tx_execution_info.validate_call_info.map(PyCallInfo::from),
            execute_call_info: tx_execution_info.execute_call_info.map(PyCallInfo::from),
            fee_transfer_call_info: tx_execution_info.fee_transfer_call_info.map(PyCallInfo::from),
            actual_fee: tx_execution_info.actual_fee.0,
            actual_resources: tx_execution_info.actual_resources.0,
        }
    }
}

pub struct PyCallInfo {
    pub caller_address: PyFelt,
    pub contract_address: PyFelt,
    pub class_hash: Option<PyFelt>,
    pub entry_point_selector: PyFelt,
    pub entry_point_type: usize,
    pub calldata: Vec<PyFelt>,
    pub retdata: Vec<PyFelt>,
    pub events: Vec<PyEvent>,
    pub l2_to_l1_messages: Vec<PyL2ToL1Message>,
}

impl From<CallInfo> for PyCallInfo {
    fn from(call_info: CallInfo) -> Self {
        let call = call_info.call;
        let class_hash = call.class_hash.map(|class_hash| PyFelt(class_hash.0));
        Self {
            caller_address: PyFelt::from(call.caller_address),
            contract_address: PyFelt::from(call.storage_address),
            class_hash,
            entry_point_selector: PyFelt(call.entry_point_selector.0),
            entry_point_type: call.entry_point_type as usize,
            calldata: starkfelt_to_pyfelt_vec(call.calldata.0.to_vec()),
            retdata: starkfelt_to_pyfelt_vec(call_info.execution.retdata.0),
            events: call_info.execution.events.into_iter().map(PyEvent::from).collect(),
            l2_to_l1_messages: call_info
                .execution
                .l2_to_l1_messages
                .into_iter()
                .map(PyL2ToL1Message::from)
                .collect(),
        }
    }
}

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

fn starkfelt_to_pyfelt_vec(vec: Vec<StarkFelt>) -> Vec<PyFelt> {
    vec.into_iter().map(PyFelt).collect()
}
