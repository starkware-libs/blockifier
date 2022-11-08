use std::path::PathBuf;

use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;

use super::cairo_run::{cairo_run, CairoRunConfig};

pub struct EntryPoint {
    /// Represents a Cairo entry point of a StarkNet contract.
    contract_file_path: PathBuf,
    selector: String,
}

impl EntryPoint {
    pub fn new(contract_file_path: &str, selector: &str) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let selector = selector.to_string();
        Self { contract_file_path, selector }
    }

    pub fn execute(&self) -> Result<(), Box<CairoRunError>> {
        cairo_run(
            &self.contract_file_path,
            &self.selector,
            CairoRunConfig::default(),
            &BuiltinHintProcessor::new_empty(),
        )
    }
}
