use std::path::PathBuf;

use cairo_rs::cairo_run;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;

pub struct CallEntryPoint {
    /// Represents a call to a Cairo entry point of a StarkNet contract.
    contract_file_path: PathBuf,
    // TODO(AlonH, 15/12/2022): Change to selector.
    name: String,
}

impl CallEntryPoint {
    pub fn new(contract_file_path: &str, name: &str) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let name = name.to_string();
        Self { contract_file_path, name }
    }

    pub fn execute(&self) -> Result<(), Box<CairoRunError>> {
        // TODO(AlonH, 15/11/2022): Create config struct for these.
        let (trace_enabled, print_output, proof_mode, layout) = (false, false, false, "all");
        cairo_run::cairo_run(
            &self.contract_file_path,
            &self.name,
            trace_enabled,
            print_output,
            layout,
            proof_mode,
            &BuiltinHintProcessor::new_empty(),
        )?;
        Ok(())
    }
}
