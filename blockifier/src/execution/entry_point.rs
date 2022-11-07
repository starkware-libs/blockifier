use std::path::PathBuf;

use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;

use super::cairo_run::{cairo_run, CairoRunConfig};

pub struct CallEntryPoint {
    /// Represents a Cairo entry point of a StarkNet contract.
    pub contract_file_path: PathBuf,
    // TODO(AlonH, 15/12/2022): Change to selector.
    pub name: String,
    pub call_data: Vec<i32>,
}

impl CallEntryPoint {
    pub fn new(contract_file_path: &str, name: &str, call_data: Vec<i32>) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let name = name.to_string();
        Self { contract_file_path, name, call_data }
    }

    pub fn execute(&self) -> Result<(), CairoRunError> {
        cairo_run(self, CairoRunConfig::default(), &BuiltinHintProcessor::new_empty())
    }
}
