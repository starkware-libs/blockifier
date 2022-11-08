use std::path::Path;

use cairo_rs::cairo_run;
use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;

pub struct CairoRunConfig {
    trace_enabled: bool,
    print_output: bool,
    layout: String,
    proof_mode: bool,
}

impl CairoRunConfig {
    pub fn default() -> Self {
        Self {
            trace_enabled: false,
            print_output: false,
            layout: "all".to_string(),
            proof_mode: false,
        }
    }
}

pub fn cairo_run(
    path: &Path,
    entrypoint: &str,
    config: CairoRunConfig,
    hint_executor: &dyn HintProcessor,
) -> Result<(), Box<CairoRunError>> {
    cairo_run::cairo_run(
        path,
        entrypoint,
        config.trace_enabled,
        config.print_output,
        &config.layout,
        config.proof_mode,
        hint_executor,
    )?;
    Ok(())
}
