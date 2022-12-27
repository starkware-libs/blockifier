use std::rc::Rc;

use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::{Calldata, EventContent, MessageToL1};

use crate::execution::contract_class::ContractClass;
use crate::execution::errors::{EntryPointExecutionError, PreExecutionError};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::state::cached_state::CachedState;
use crate::state::state_reader::StateReader;

#[cfg(test)]
#[path = "entry_point_test.rs"]
pub mod test;

pub type EntryPointExecutionResult<T> = Result<T, EntryPointExecutionError>;

/// Represents a call to an entry point of a StarkNet contract.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CallEntryPoint {
    // The class_hash is not given if it can be deduced from the storage address.
    pub class_hash: Option<ClassHash>,
    pub entry_point_type: EntryPointType,
    pub entry_point_selector: EntryPointSelector,
    // Appears in several locations during and after execution.
    pub calldata: Calldata,
    pub storage_address: ContractAddress,
}

impl CallEntryPoint {
    pub fn execute<SR: StateReader>(
        self,
        state: &mut CachedState<SR>,
    ) -> EntryPointExecutionResult<CallInfo> {
        execute_entry_point_call(self, state)
    }

    pub fn resolve_entry_point_pc(
        &self,
        contract_class: &ContractClass,
    ) -> Result<usize, PreExecutionError> {
        let entry_points_of_same_type =
            &contract_class.entry_points_by_type[&self.entry_point_type];

        // TODO(Noa, 30/12/22): Handle the case where filtered_entry_points.len() == 0 and
        // entry_points.len() > 0

        match entry_points_of_same_type.iter().find(|ep| ep.selector == self.entry_point_selector) {
            Some(entry_point) => Ok(entry_point.offset.0),
            None => Err(PreExecutionError::EntryPointNotFound(self.entry_point_selector)),
        }
    }

    pub fn validate_contract_deployed_and_get_class_hash<SR: StateReader>(
        &self,
        state: &mut CachedState<SR>,
    ) -> Result<ClassHash, PreExecutionError> {
        let storage_class_hash = *state.get_class_hash_at(self.storage_address)?;
        if storage_class_hash == ClassHash::default() {
            return Err(PreExecutionError::UninitializedContract(self.storage_address));
        }

        match self.class_hash {
            Some(class_hash) => Ok(class_hash),
            None => Ok(storage_class_hash),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Retdata(pub Rc<Vec<StarkFelt>>);

#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallExecution {
    pub retdata: Retdata,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallInfo {
    pub call: CallEntryPoint,
    pub execution: CallExecution,
    pub inner_calls: Vec<CallInfo>,
    pub events: Vec<EventContent>,
    pub l2_to_l1_messages: Vec<MessageToL1>,
}

pub fn execute_constructor_entry_point<SR: StateReader>(
    state: &mut CachedState<SR>,
    class_hash: ClassHash,
    storage_address: ContractAddress,
    calldata: Calldata,
) -> EntryPointExecutionResult<CallInfo> {
    let contract_class = state.get_contract_class(&class_hash)?;
    let constructor_entry_points =
        &contract_class.entry_points_by_type[&EntryPointType::Constructor];

    if constructor_entry_points.is_empty() {
        // Contract has no constructor.
        return handle_empty_constructor(class_hash, storage_address, calldata);
    }

    let constructor_call = CallEntryPoint {
        class_hash: Some(class_hash),
        entry_point_type: EntryPointType::Constructor,
        entry_point_selector: constructor_entry_points[0].selector,
        calldata,
        storage_address,
    };
    constructor_call.execute(state)
}

pub fn handle_empty_constructor(
    class_hash: ClassHash,
    storage_address: ContractAddress,
    calldata: Calldata,
) -> EntryPointExecutionResult<CallInfo> {
    // Validate no calldata.
    if calldata.0.is_empty() {
        return Err(EntryPointExecutionError::InvalidExecutionInput {
            input: StarkFelt::from(calldata.0.len() as u64),
            info: String::from("Cannot pass calldata to a contract with no constructor."),
        });
    }

    let empty_constructor_call_info = CallInfo {
        call: CallEntryPoint {
            class_hash: Some(class_hash),
            entry_point_type: EntryPointType::Constructor,
            // TODO(Noa, 30/12/22):Use
            // get_selector_from_name(func_name=CONSTRUCTOR_ENTRY_POINT_NAME).
            entry_point_selector: EntryPointSelector(StarkHash::default()),
            calldata: Calldata::default(),
            storage_address,
        },
        ..Default::default()
    };

    Ok(empty_constructor_call_info)
}
