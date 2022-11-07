use std::path::PathBuf;

use cairo_rs::cairo_run;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;

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
        let (trace_enabled, print_output, layout) = (false, false, "all");
        cairo_run::cairo_run(
            &self.contract_file_path,
            &self.entry_point,
            trace_enabled,
            print_output,
            layout,
            &BuiltinHintProcessor::new_empty(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_entry_point() {
        let test_contract = "./test_contracts/array_sum.json";
        let test_entry_point = ExecuteEntryPoint::new(test_contract, "main");
        if let Err(error) = test_entry_point.execute() {
            panic!("Error: {error}");
        }
    }
}
