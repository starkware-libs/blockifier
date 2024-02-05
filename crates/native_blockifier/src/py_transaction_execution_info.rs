use std::collections::{HashMap, HashSet};

use blockifier::abi::constants;
use blockifier::execution::call_info::{CallInfo, OrderedEvent, OrderedL2ToL1Message};
use blockifier::execution::entry_point::CallType;
use blockifier::transaction::objects::{
    ResourcesMapping, TransactionExecutionInfo, TransactionExecutionResult,
};
use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pyo3::prelude::*;
use starknet_api::deprecated_contract_class::EntryPointType;

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
    pub entry_point_type: PyEntryPointType,
    #[pyo3(get)]
    pub calldata: Vec<PyFelt>,
    #[pyo3(get)]
    pub call_type: PyCallType,

    // Call results.
    #[pyo3(get)]
    pub gas_consumed: u64, // Currently not in use.
    #[pyo3(get)]
    pub failure_flag: bool, // Currently not in use.
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

#[pyclass]
#[derive(Clone)]
pub enum PyCallType {
    Call = 0,
    Delegate = 1,
}

impl From<CallType> for PyCallType {
    fn from(call_type: CallType) -> Self {
        match call_type {
            CallType::Call => PyCallType::Call,
            CallType::Delegate => PyCallType::Delegate,
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub enum PyEntryPointType {
    Constructor,
    External,
    L1Handler,
}

impl From<EntryPointType> for PyEntryPointType {
    fn from(enrty_point_type: EntryPointType) -> Self {
        match enrty_point_type {
            EntryPointType::Constructor => PyEntryPointType::Constructor,
            EntryPointType::External => PyEntryPointType::External,
            EntryPointType::L1Handler => PyEntryPointType::L1Handler,
        }
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
            entry_point_type: PyEntryPointType::from(call.entry_point_type),
            calldata: to_py_vec(call.calldata.0.to_vec(), PyFelt),
            gas_consumed: execution.gas_consumed,
            failure_flag: execution.failed,
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
            call_type: PyCallType::from(call.call_type),
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
        Self {
            order: ordered_event.order,
            keys: to_py_vec(ordered_event.event.keys, |x| PyFelt(x.0)),
            data: to_py_vec(ordered_event.event.data.0, PyFelt),
        }
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
        Self {
            order: ordered_message.order,
            to_address: PyFelt::from(ordered_message.message.to_address),
            payload: to_py_vec(ordered_message.message.payload.0, PyFelt),
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

#[pyclass]
#[derive(Clone, Default)]
pub struct PyBouncerInfo {
    #[pyo3(get)]
    pub state_diff_size: usize, // The number of felts needed to store the state diff.
    #[pyo3(get)]
    pub l1_gas_amount: usize,
    #[pyo3(get)]
    pub message_segment_length: usize, // The number of felts needed to store L1<>L2 messages.
    #[pyo3(get)]
    pub execution_resources: PyVmExecutionResources,
}

impl PyBouncerInfo {
    pub fn calculate(
        tx_actual_resources: &ResourcesMapping,
        tx_additional_os_resources: VmExecutionResources,
        message_segment_length: usize,
        state_diff_size: usize,
    ) -> TransactionExecutionResult<Self> {
        let l1_gas_amount = *tx_actual_resources
            .0
            .get("l1_gas_usage")
            .expect("Invalid Transaction Execution Info. Field l1_gas_usage was not found.");

        // TODO(Ayelet, 04/02/2024): Consider defining a constant list.
        let builtin_ordered_list = [
            BuiltinName::output,
            BuiltinName::pedersen,
            BuiltinName::range_check,
            BuiltinName::ecdsa,
            BuiltinName::bitwise,
            BuiltinName::ec_op,
            BuiltinName::keccak,
            BuiltinName::poseidon,
        ];
        let builtin_instance_counter: HashMap<String, usize> = builtin_ordered_list
            .iter()
            .map(|name| {
                (
                    name.name().to_string(),
                    tx_actual_resources.0.get(name.name()).copied().unwrap_or_default(),
                )
            })
            .collect();
        let tx_actual_resources = VmExecutionResources {
            n_steps: tx_actual_resources
                .0
                .get(constants::N_STEPS_RESOURCE)
                .copied()
                .unwrap_or_default(),
            n_memory_holes: tx_actual_resources
                .0
                .get("n_memory_holes")
                .copied()
                .unwrap_or_default(),
            builtin_instance_counter,
        };

        let mut merged_resources = &tx_additional_os_resources + &tx_actual_resources;
        // Memory holes are counted as steps.
        merged_resources.n_steps += merged_resources.n_memory_holes;
        merged_resources.n_memory_holes = 0;

        Ok(Self {
            state_diff_size,
            l1_gas_amount,
            message_segment_length,
            execution_resources: PyVmExecutionResources::from(merged_resources),
        })
    }
}
