use std::path::Path;
use anyhow::{Context, Result};

use cairo_rs::cairo_run;
use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;

#[derive(Debug)]
pub enum Layout {
    All
}

impl From<Layout> for String {
    fn from(layout: Layout) -> Self {
        format!("{:?}", layout).to_ascii_lowercase()
    }
}

pub struct CairoRunConfig {
    trace_enabled: bool,
    print_output: bool,
    layout: Layout,
    proof_mode: bool,
}

impl CairoRunConfig {
    pub fn default() -> Self {
        Self {
            trace_enabled: false,
            print_output: false,
            layout: Layout::All,
            proof_mode: false,
        }
    }
}

pub fn cairo_run(
    path: &Path,
    entry_point_name: &str,
    config: CairoRunConfig,
    hint_executor: &dyn HintProcessor,
) -> Result<()> {
    let layout: String = config.layout.into();
    cairo_run::cairo_run(
        path,
        entry_point_name,
        config.trace_enabled,
        config.print_output,
        &layout,
        config.proof_mode,
        hint_executor,
    ).context(format!(
        "Failed to execute entry point '{}' in file path '{}'.",
        entry_point_name, path.display()
    ))?;
    Ok(())
}
