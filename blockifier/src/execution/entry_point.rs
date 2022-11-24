use std::path::PathBuf;

use anyhow::Result;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use num_bigint::BigInt;
use starknet_api::{EntryPoint, EntryPointSelector, EntryPointType};

use super::cairo_run_utils::{execute_call_entry_point, CairoRunConfig};
use crate::execution::contract_class::ContractClass;

/// Represents a call to an entry point of a StarkNet contract.
pub struct CallEntryPoint {
    pub contract_class: ContractClass,
    pub contract_file_path: PathBuf,
    // TODO(Noa, 27/11/2022): Remove.
    pub name: String,
    pub calldata: Vec<i32>,
    pub entry_point_selector: EntryPointSelector,
    pub entry_point_type: EntryPointType,
}

impl CallEntryPoint {
    pub fn new(
        contract_class: ContractClass,
        contract_file_path: &str,
        name: &str,
        calldata: Vec<i32>,
        entry_point_selector: EntryPointSelector,
        entry_point_type: EntryPointType,
    ) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let name = name.to_string();
        Self {
            contract_class,
            contract_file_path,
            name,
            calldata,
            entry_point_selector,
            entry_point_type,
        }
    }

    pub fn execute(&self) -> Result<Vec<BigInt>> {
        let entry_point = self._get_selected_entry_point();
        // Returns the output of the entry point execution.
        execute_call_entry_point(
            self,
            CairoRunConfig::default(),
            &BuiltinHintProcessor::new_empty(),
            &entry_point?,
        )
    }

    fn _get_selected_entry_point(&self) -> Result<EntryPoint> {
        let entry_points = &self.contract_class.entry_points_by_type[&self.entry_point_type];
        let filtered_entry_points: Vec<&EntryPoint> =
            entry_points.iter().filter(|ep| ep.selector == self.entry_point_selector).collect();
        // TODO(Noa, 30/12/22): Handle the case where filtered_entry_points.len() == 0 and
        // entry_points.len() > 0

        // TODO(Noa, 30/12/22): assert filtered_entry_points.len() == 1
        Ok(filtered_entry_points[0].clone())
    }
}
