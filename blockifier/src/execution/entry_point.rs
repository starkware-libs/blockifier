use std::path::PathBuf;

use anyhow::Result;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use starknet_api::StarkFelt;

use super::cairo_run_utils::{execute_call_entry_point, CairoRunConfig};
use crate::execution::contract_class::ContractClass;

/// Represents a call to an entry point of a StarkNet contract.
pub struct CallEntryPoint {
    /// Represents a Cairo entry point of a StarkNet contract.
    pub contract_class: ContractClass,
    pub contract_file_path: PathBuf,
    // TODO(AlonH, 15/12/2022): Change to selector.
    pub name: String,
    pub calldata: Vec<i32>,
}

impl CallEntryPoint {
    pub fn new(
        contract_class: ContractClass,
        contract_file_path: &str,
        name: &str,
        calldata: Vec<i32>,
    ) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let name = name.to_string();
        Self { contract_class, contract_file_path, name, calldata }
    }

    pub fn execute(&self) -> Result<Vec<StarkFelt>> {
        // Returns the output of the entry point execution.
        execute_call_entry_point(
            self,
            CairoRunConfig::default(),
            &BuiltinHintProcessor::new_empty(),
        )
    }
}
