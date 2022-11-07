use anyhow::Result;
use cairo_rs::cairo_run::write_output;
use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
use cairo_rs::types::program::Program;
use cairo_rs::types::relocatable::MaybeRelocatable;
use cairo_rs::vm::runners::cairo_runner::CairoRunner;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

use super::entry_point::CallEntryPoint;

#[derive(Debug)]
pub enum Layout {
    All,
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
        Self { trace_enabled: false, print_output: false, layout: Layout::All, proof_mode: false }
    }
}

pub fn cairo_run(
    call: &CallEntryPoint,
    config: CairoRunConfig,
    hint_executor: &dyn HintProcessor,
) -> Result<()> {
    let layout: String = config.layout.into();
    let program = Program::from_file(&call.contract_file_path, Some(&call.name))?;

    let mut cairo_runner = CairoRunner::new(&program, &layout, config.proof_mode)?;
    let mut vm = VirtualMachine::new(program.prime, config.trace_enabled);
    let entry_point_pc =
        program.identifiers.get(&format!("__main__.{}", &call.name)).unwrap().pc.unwrap();

    let mut args = Vec::<MaybeRelocatable>::new();
    for arg in &call.call_data {
        args.push(MaybeRelocatable::Int(bigint!(*arg)));
    }

    cairo_runner.initialize_function_runner(&mut vm)?;
    cairo_runner.run_from_entrypoint(
        entry_point_pc,
        vec![&args],
        true,
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
