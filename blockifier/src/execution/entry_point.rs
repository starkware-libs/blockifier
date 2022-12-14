use starknet_api::core::{ClassHash, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::CallData;

use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::contract_class::ContractClass;
use crate::execution::errors::{EntryPointExecutionError, PreExecutionError};
use crate::execution::execution_utils::execute_call_entry_point;

#[cfg(test)]
#[path = "entry_point_test.rs"]
pub mod test;

pub type EntryPointResult<T> = Result<T, EntryPointExecutionError>;

/// Represents a call to an entry point of a StarkNet contract.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CallEntryPoint {
    pub class_hash: ClassHash,
    pub entry_point_type: EntryPointType,
    pub entry_point_selector: EntryPointSelector,
    pub calldata: CallData,
}

impl CallEntryPoint {
    // TODO(Noa, 18/12/22): Add a new() method that extract the class_hash from the storage_address
    // in case of a call_contract entry_point
    pub fn execute(&self, state: CachedState<DictStateReader>) -> EntryPointResult<CallInfo> {
        // Returns the output of the entry point execution.
        execute_call_entry_point(self, state)
    }

    pub fn find_entry_point_pc_in_contract(
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
