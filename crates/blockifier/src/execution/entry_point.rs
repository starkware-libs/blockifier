use std::collections::HashSet;

use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{EntryPoint, EntryPointType, StorageKey};
use starknet_api::transaction::{Calldata, EventContent, MessageToL1};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants::{CONSTRUCTOR_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR};
use crate::block_context::BlockContext;
use crate::execution::contract_class::ContractClass;
use crate::execution::errors::{EntryPointExecutionError, PreExecutionError};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::execution::syscall_handling::SyscallCounter;
use crate::state::state_api::State;
use crate::transaction::objects::AccountTransactionContext;

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
    }

    pub fn resolve_entry_point_pc(
        &self,
        contract_class: &ContractClass,
    ) -> Result<usize, PreExecutionError> {
        let entry_points_of_same_type =
            &contract_class.entry_points_by_type[&self.entry_point_type];
        let filtered_entry_points: Vec<&EntryPoint> = entry_points_of_same_type
            .iter()
            .filter(|ep| ep.selector == self.entry_point_selector)
            .collect();

        // Returns the default entrypoint if the given selector is missing.
        if filtered_entry_points.is_empty() {
            match entry_points_of_same_type.get(0) {
                Some(entry_point) => {
                    if entry_point.selector
                        == EntryPointSelector(DEFAULT_ENTRY_POINT_SELECTOR.into())
                    {
                        return Ok(entry_point.offset.0);
                    } else {
                        return Err(PreExecutionError::EntryPointNotFound(
                            self.entry_point_selector,
                        ));
                    }
                }
                None => {
                    return Err(PreExecutionError::NoEntryPointOfTypeFound(
                        self.entry_point_type.clone(),
                    ));
                }
            }
        }

        if filtered_entry_points.len() > 1 {
            return Err(PreExecutionError::DuplicateSelector {
                selector: self.entry_point_selector,
                n_matches: filtered_entry_points.len(),
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
    storage_address: ContractAddress,
    caller_address: ContractAddress,
    calldata: Calldata,
) -> EntryPointExecutionResult<CallInfo> {
    // Ensure the class is declared (by reading it).
    let contract_class = state.get_contract_class(&class_hash)?;
    let constructor_entry_points =
        &contract_class.entry_points_by_type[&EntryPointType::Constructor];

    if constructor_entry_points.is_empty() {
        // Contract has no constructor.
        return handle_empty_constructor(class_hash, calldata, storage_address, caller_address);
    }

    let constructor_call = CallEntryPoint {
        class_hash: None,
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
