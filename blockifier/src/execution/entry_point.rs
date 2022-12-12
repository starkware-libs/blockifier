use anyhow::{Context, Result};
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::StarkFelt;
use starknet_api::state::{EntryPoint, EntryPointType};
use starknet_api::transaction::CallData;

use crate::execution::contract_class::ContractClass;
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::execution_utils::{execute_call_entry_point, CairoRunConfig};

pub type EntryPointResult<T> = Result<T, EntryPointExecutionError>;

/// Represents a call to an entry point of a StarkNet contract.
pub struct CallEntryPoint {
    pub contract_class: ContractClass,
    pub entry_point_type: EntryPointType,
    pub entry_point_selector: EntryPointSelector,
    pub calldata: CallData,
}

impl CallEntryPoint {
    pub fn execute(&self) -> Result<Vec<StarkFelt>> {
        // Returns the output of the entry point execution.
        execute_call_entry_point(self, CairoRunConfig::default())
    }

    pub fn find_entry_point_in_contract(&self) -> Result<&EntryPoint> {
        let entry_points_of_same_type =
            &self.contract_class.entry_points_by_type[&self.entry_point_type];

        // TODO(Noa, 30/12/22): Handle the case where filtered_entry_points.len() == 0 and
        // entry_points.len() > 0

        entry_points_of_same_type
            .iter()
            .find(|ep| ep.selector == self.entry_point_selector)
            .context(format!("Entry point {:#?} not found in contract", self.entry_point_selector))
    }
}
