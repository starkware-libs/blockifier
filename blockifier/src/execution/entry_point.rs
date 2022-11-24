use std::path::PathBuf;

use anyhow::{Context, Result};
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use num_bigint::BigInt;
use starknet_api::{EntryPoint, EntryPointSelector, EntryPointType};

use super::cairo_run_utils::{execute_call_entry_point, CairoRunConfig};
use crate::execution::contract_class::ContractClass;

/// Represents a call to an entry point of a StarkNet contract.
pub struct CallEntryPoint {
    pub contract_class: ContractClass,
    pub contract_file_path: PathBuf,
    pub entry_point_type: EntryPointType,
    pub entry_point_selector: EntryPointSelector,
    pub calldata: Vec<i32>,
}

impl CallEntryPoint {
    pub fn new(
        contract_class: ContractClass,
        contract_file_path: &str,
        entry_point_type: EntryPointType,
        entry_point_selector: EntryPointSelector,
        calldata: Vec<i32>,
    ) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        Self {
            contract_class,
            contract_file_path,
            entry_point_type,
            entry_point_selector,
            calldata,
        }
    }

    pub fn execute(&self) -> Result<Vec<BigInt>> {
        // Returns the output of the entry point execution.
        execute_call_entry_point(
            self,
            CairoRunConfig::default(),
            &BuiltinHintProcessor::new_empty(),
            self.get_selected_entry_point()?,
        )
    }

    fn get_selected_entry_point(&self) -> Result<&EntryPoint> {
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
