use std::path::PathBuf;

use anyhow::Result;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use num_bigint::BigInt;

use super::cairo_run_utils::{cairo_run, CairoRunConfig};

pub struct CallEntryPoint {
    /// Represents a Cairo entry point of a StarkNet contract.
    pub contract_file_path: PathBuf,
    // TODO(AlonH, 15/12/2022): Change to selector.
    pub name: String,
    pub calldata: Vec<i32>,
}

impl CallEntryPoint {
    pub fn new(contract_file_path: &str, name: &str, calldata: Vec<i32>) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let name = name.to_string();
        Self { contract_file_path, name, calldata }
    }

    pub fn execute(&self) -> Result<Vec<BigInt>> {
        cairo_run(self, CairoRunConfig::default(), &BuiltinHintProcessor::new_empty())
    }
}
