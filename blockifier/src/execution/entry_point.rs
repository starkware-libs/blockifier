use std::path::PathBuf;

use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;

use super::cairo_run::{cairo_run, CairoRunConfig};

pub struct ExecuteEntryPoint {
    contract_file_path: PathBuf,
    entry_point: String,
}

impl ExecuteEntryPoint {
    pub fn new(contract_file_path: &str, entry_point: &str) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let entry_point = entry_point.to_string();
        Self { contract_file_path, entry_point }
    }

    pub fn execute(&self) -> Result<(), Box<CairoRunError>> {
        cairo_run(
            &self.contract_file_path,
            &self.entry_point,
            CairoRunConfig::default(),
            &BuiltinHintProcessor::new_empty(),
        )
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_execute_entry_point() -> Result<(), Box<CairoRunError>> {
        let test_contract = "./test_contracts/array_sum.json";
        let test_entry_point = ExecuteEntryPoint::new(test_contract, "main");
        assert_eq!(test_entry_point.execute()?, ());
        Ok(())
    }
}
