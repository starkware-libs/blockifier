use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::CallData;

use crate::execution::contract_class::ContractClass;
use crate::execution::errors::{EntryPointExecutionError, PreExecutionError};
use crate::execution::execution_utils::execute_entry_point_call;
use crate::state::cached_state::{CachedState, DictStateReader};

#[cfg(test)]
#[path = "entry_point_test.rs"]
pub mod test;

pub type EntryPointResult<T> = Result<T, EntryPointExecutionError>;

// TODO(Adi, 15/10/2023): Change calldata field to have a reference to a CallData object and change
// calldata cloning everywhere. Same for objects containing CallEntryPoint, and for retdata.
/// Represents a call to an entry point of a StarkNet contract.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CallEntryPoint {
    // TODO(Noa, 18/12/22): Consider changing class_hash to be optional + add a method to extract
    // it from the storage_address (get_non_optional_class_hash)
    pub class_hash: ClassHash,
    pub entry_point_type: EntryPointType,
    pub entry_point_selector: EntryPointSelector,
    pub calldata: CallData,
    pub storage_address: ContractAddress,
}

impl CallEntryPoint {
    pub fn execute(self, state: &mut CachedState<DictStateReader>) -> EntryPointResult<CallInfo> {
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
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallExecution {
    pub retdata: Vec<StarkFelt>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallInfo {
    pub call: CallEntryPoint,
    pub execution: CallExecution,
    pub inner_calls: Vec<CallInfo>,
}

impl CallInfo {
    pub fn create_for_empty_constructor_call(
        class_hash: ClassHash,
        storage_address: ContractAddress,
    ) -> CallInfo {
        CallInfo {
            call: CallEntryPoint {
                class_hash,
                entry_point_type: EntryPointType::Constructor,
                // TODO(Noa, 30/12/22):Use
                // get_selector_from_name(func_name=CONSTRUCTOR_ENTRY_POINT_NAME).
                entry_point_selector: EntryPointSelector(StarkHash::default()),
                calldata: CallData::default(),
                storage_address,
            },
            execution: CallExecution { retdata: vec![] },
            inner_calls: vec![],
        }
    }
}

pub fn execute_constructor_entry_point(
    state: &mut CachedState<DictStateReader>,
    class_hash: ClassHash,
    storage_address: ContractAddress,
    calldata: &CallData,
) -> EntryPointResult<CallInfo> {
    let contract_class = state.get_contract_class(&class_hash)?;
    let constructor_entry_points =
        &contract_class.entry_points_by_type[&EntryPointType::Constructor];

    if constructor_entry_points.is_empty() {
        // Contract has no constructor.
        if !calldata.0.is_empty() {
            return Err(EntryPointExecutionError::InvalidExecutationInput {
                input: StarkFelt::from(calldata.0.len() as u64),
                info: String::from("Cannot pass calldata to a contract with no constructor."),
            });
        }
        return Ok(CallInfo::create_for_empty_constructor_call(class_hash, storage_address));
    }

    let entry_point = CallEntryPoint {
        class_hash,
        entry_point_type: EntryPointType::Constructor,
        entry_point_selector: constructor_entry_points[0].selector,
        calldata: calldata.clone(),
        storage_address,
    };
    entry_point.execute(state)
}
