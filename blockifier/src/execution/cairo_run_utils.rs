use std::any::Any;

use anyhow::Result;
use cairo_rs::bigint;
use cairo_rs::cairo_run::write_output;
use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
use cairo_rs::types::program::Program;
use cairo_rs::types::relocatable::MaybeRelocatable;
use cairo_rs::vm::runners::cairo_runner::CairoRunner;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

use crate::execution::entry_point::CallEntryPoint;

#[derive(Debug)]
pub enum Layout {
    All,
}

impl From<Layout> for String {
    fn from(layout: Layout) -> Self {
        // The Cairo runner is expecting `layout` to be a lowercase string.
        format!("{:?}", layout).to_ascii_lowercase()
    }
}

pub struct CairoRunConfig {
    pub enable_trace: bool,
    pub print_output: bool,
    pub layout: Layout,
    pub proof_mode: bool,
}

impl CairoRunConfig {
    pub fn default() -> Self {
        Self { enable_trace: false, print_output: false, layout: Layout::All, proof_mode: false }
    }
}

pub fn cairo_run(
    call_entry_point: &CallEntryPoint,
    config: CairoRunConfig,
    hint_executor: &dyn HintProcessor,
) -> Result<()> {
    let layout: String = config.layout.into();
    let program =
        Program::from_file(&call_entry_point.contract_file_path, Some(&call_entry_point.name))?;

    let mut cairo_runner = CairoRunner::new(&program, &layout, config.proof_mode)?;
    let mut vm = VirtualMachine::new(program.prime, config.enable_trace);

    let entry_point_pc = program
        .identifiers
        .get(&format!("__main__.{}", &call_entry_point.name))
        .unwrap_or_else(|| panic!("Entry point {} not found in {}.",
            &call_entry_point.name,
            &call_entry_point.contract_file_path.display()))
        .pc
        .unwrap_or_else(|| panic!("Identifier {} is not an entry point.",
            &call_entry_point.name));

    let mut args = Vec::<MaybeRelocatable>::new();
    for arg in &call_entry_point.call_data {
        // TODO(AlonH, 21/12/2022): Consider using StarkFelt.
        args.push(MaybeRelocatable::Int(bigint!(*arg)));
    }

    cairo_runner.initialize_function_runner(&mut vm)?;
    cairo_runner.run_from_entrypoint(
        entry_point_pc,
        args.iter().map(|x| x as &dyn Any).collect(),
        false,
        true,
        true,
        &mut vm,
        hint_executor,
    )?;

    if config.print_output {
        write_output(&mut cairo_runner, &mut vm)?;
    }

    Ok(())
}
