use std::collections::HashSet;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::{EntryPoint, EntryPointType};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, EthAddress, EventContent, L2ToL1Payload};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants::{CONSTRUCTOR_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR};
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClassV0;
use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::errors::{EntryPointExecutionError, PreExecutionError};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::state::state_api::State;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{AccountTransactionContext, TransactionExecutionResult};

#[cfg(test)]
#[path = "entry_point_test.rs"]
pub mod test;

pub type EntryPointExecutionResult<T> = Result<T, EntryPointExecutionError>;

/// Represents a the type of the call (used for debugging).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum CallType {
    #[default]
    Call = 0,
    Delegate = 1,
}
/// Represents a call to an entry point of a StarkNet contract.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CallEntryPoint {
    // The class hash is not given if it can be deduced from the storage address.
    pub class_hash: Option<ClassHash>,
    // Optional, since there is no address to the code implementation in a library call.
    // and for outermost calls (triggered by the transaction itself).
    // TODO: BACKWARD-COMPATIBILITY.
    pub code_address: Option<ContractAddress>,
    pub entry_point_type: EntryPointType,
    pub entry_point_selector: EntryPointSelector,
    pub calldata: Calldata,
    pub storage_address: ContractAddress,
    pub caller_address: ContractAddress,
    pub call_type: CallType,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ExecutionResources {
    pub vm_resources: VmExecutionResources,
    pub syscall_counter: SyscallCounter,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ExecutionContext {
    // Used for tracking events order during the current execution.
    pub n_emitted_events: usize,
    // Used for tracking L2-to-L1 messages order during the current execution.
    pub n_sent_messages_to_l1: usize,
    // Used to track error stack for call chain.
    pub error_stack: Vec<(ContractAddress, String)>,
}

impl ExecutionContext {
    /// Combines individual errors into a single stack trace string, with contract addresses printed
    /// alongside their respective trace.
    pub fn error_trace(&self) -> String {
        let mut frame_errors: Vec<String> = vec![];
        for (contract_address, trace_string) in self.error_stack.iter().rev() {
            frame_errors.push(format!(
                "Error in the called contract ({}):\n{}",
                contract_address.0.key(),
                trace_string
            ));
        }
        frame_errors.join("\n")
    }
}

impl CallEntryPoint {
    pub fn execute(
        mut self,
        state: &mut dyn State,
        execution_resources: &mut ExecutionResources,
        execution_context: &mut ExecutionContext,
        block_context: &BlockContext,
        account_tx_context: &AccountTransactionContext,
    ) -> EntryPointExecutionResult<CallInfo> {
        // Validate contract is deployed.
        let storage_address = self.storage_address;
        let storage_class_hash = state.get_class_hash_at(self.storage_address)?;
        if storage_class_hash == ClassHash::default() {
            return Err(PreExecutionError::UninitializedStorageAddress(self.storage_address).into());
        }

        let class_hash = match self.class_hash {
            Some(class_hash) => class_hash,
            None => storage_class_hash, // If not given, take the storage contract class hash.
        };
        // Add class hash to the call, that will appear in the output (call info).
        self.class_hash = Some(class_hash);

        execute_entry_point_call(
            self,
            class_hash,
            state,
            execution_resources,
            execution_context,
            block_context,
            account_tx_context,
        )
        .map_err(|error| match error {
            // On VM error, pack the stack trace into the propagated error.
            EntryPointExecutionError::VirtualMachineExecutionError(error) => {
                execution_context.error_stack.push((storage_address, error.try_to_vm_trace()));
                // TODO(Dori, 1/5/2023): Call error_trace only in the top call; as it is right now,
                //  each intermediate VM error is wrapped in a VirtualMachineExecutionErrorWithTrace
                //  error with the stringified trace of all errors below it.
                EntryPointExecutionError::VirtualMachineExecutionErrorWithTrace {
                    trace: execution_context.error_trace(),
                    source: error,
                }
            }
            other_error => other_error,
        })
    }

    pub fn resolve_entry_point_pc(
        &self,
        contract_class: &ContractClassV0,
    ) -> Result<usize, PreExecutionError> {
        let entry_points_of_same_type =
            &contract_class.0.entry_points_by_type[&self.entry_point_type];
        let filtered_entry_points: Vec<&EntryPoint> = entry_points_of_same_type
            .iter()
            .filter(|ep| ep.selector == self.entry_point_selector)
            .collect();

        // Returns the default entrypoint if the given selector is missing.
        if filtered_entry_points.is_empty() {
            match entry_points_of_same_type.get(0) {
                Some(entry_point) => {
                    if entry_point.selector
                        == EntryPointSelector(StarkHash::from(DEFAULT_ENTRY_POINT_SELECTOR))
                    {
                        return Ok(entry_point.offset.0);
                    } else {
                        return Err(PreExecutionError::EntryPointNotFound(
                            self.entry_point_selector,
                        ));
                    }
                }
                None => {
                    return Err(PreExecutionError::NoEntryPointOfTypeFound(self.entry_point_type));
                }
            }
        }

        if filtered_entry_points.len() > 1 {
            return Err(PreExecutionError::DuplicatedEntryPointSelector {
                selector: self.entry_point_selector,
                typ: self.entry_point_type,
            });
        }

        // Filtered entry points contain exactly one element.
        let entry_point = filtered_entry_points
            .get(0)
            .expect("The number of entry points with the given selector is exactly one.");
        Ok(entry_point.offset.0)
    }
}

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
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallExecution {
    pub retdata: Retdata,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
}

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
    pub fn get_executed_class_hashes(&self) -> HashSet<ClassHash> {
        let mut class_hashes = HashSet::<ClassHash>::from([self
            .call
            .class_hash
            .expect("Class hash must be set after execution.")]);

        for call in self.into_iter() {
            class_hashes.extend(call.get_executed_class_hashes());
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
                if starknet_l2_to_l1_payloads_length[ordered_message_content.order].is_some() {
                    return Err(TransactionExecutionError::UnexpectedHoles {
                        object: "L2-to-L1 message".to_string(),
                        order: ordered_message_content.order,
                    });
                }
                starknet_l2_to_l1_payloads_length[ordered_message_content.order] =
                    Some(ordered_message_content.message.payload.0.len());
            }
        }

        Ok(starknet_l2_to_l1_payloads_length.into_iter().flatten().collect())
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

#[allow(clippy::too_many_arguments)]
pub fn execute_constructor_entry_point(
    state: &mut dyn State,
    execution_resources: &mut ExecutionResources,
    execution_context: &mut ExecutionContext,
    block_context: &BlockContext,
    account_tx_context: &AccountTransactionContext,
    class_hash: ClassHash,
    code_address: Option<ContractAddress>,
    storage_address: ContractAddress,
    caller_address: ContractAddress,
    calldata: Calldata,
) -> EntryPointExecutionResult<CallInfo> {
    // Ensure the class is declared (by reading it).
    let contract_class = state.get_compiled_contract_class(&class_hash)?;
    let constructor_entry_points =
        &contract_class.0.entry_points_by_type[&EntryPointType::Constructor];

    if constructor_entry_points.is_empty() {
        // Contract has no constructor.
        return handle_empty_constructor(
            class_hash,
            code_address,
            calldata,
            storage_address,
            caller_address,
        );
    }

    let constructor_call = CallEntryPoint {
        class_hash: None,
        code_address,
        entry_point_type: EntryPointType::Constructor,
        entry_point_selector: constructor_entry_points[0].selector,
        calldata,
        storage_address,
        caller_address,
        call_type: CallType::Call,
    };

    constructor_call.execute(
        state,
        execution_resources,
        execution_context,
        block_context,
        account_tx_context,
    )
}

pub fn handle_empty_constructor(
    class_hash: ClassHash,
    code_address: Option<ContractAddress>,
    calldata: Calldata,
    storage_address: ContractAddress,
    caller_address: ContractAddress,
) -> EntryPointExecutionResult<CallInfo> {
    // Validate no calldata.
    if !calldata.0.is_empty() {
        return Err(EntryPointExecutionError::InvalidExecutionInput {
            input_descriptor: "constructor_calldata".to_string(),
            info: "Cannot pass calldata to a contract with no constructor.".to_string(),
        });
    }

    let empty_constructor_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: Some(class_hash),
            code_address,
            entry_point_type: EntryPointType::Constructor,
            entry_point_selector: selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME),
            calldata: Calldata::default(),
            storage_address,
            caller_address,
            call_type: CallType::Call,
        },
        ..Default::default()
    };

    Ok(empty_constructor_call_info)
}
