use std::any::Any;

use anyhow::{bail, Result};
use cairo_rs::bigint;
use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
use cairo_rs::types::program::Program;
use cairo_rs::types::relocatable::MaybeRelocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
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
    pub layout: Layout,
    pub proof_mode: bool,
}

impl CairoRunConfig {
    pub fn default() -> Self {
        Self { enable_trace: false, layout: Layout::All, proof_mode: false }
    }
}

pub fn cairo_run(
    call_entry_point: &CallEntryPoint,
    config: CairoRunConfig,
    hint_executor: &dyn HintProcessor,
) -> Result<Vec<BigInt>> {
    let layout: String = config.layout.into();
    let program =
        Program::from_file(&call_entry_point.contract_file_path, Some(&call_entry_point.name))?;

    let mut cairo_runner = CairoRunner::new(&program, &layout, config.proof_mode)?;
    let mut vm = VirtualMachine::new(program.prime, config.enable_trace);
    // TODO(AlonH, 21/11/2022): Remove `unwrap`s and handle errors instead.
    let entry_point_pc = program
        .identifiers
        .get(&format!("__wrappers__.{}", &call_entry_point.name))
        .unwrap()
        .pc
        .unwrap();

    cairo_runner.initialize_function_runner(&mut vm)?;

    let mut args: Vec<Box<dyn Any>> = Vec::new();
    // TODO(AlonH, 21/12/2022): Push the entry point selector to args once it is used.
    let os_context: Vec<MaybeRelocatable> = vm
        .get_builtin_runners()
        .iter()
        .flat_map(|(_name, builtin_runner)| builtin_runner.initial_stack())
        .collect();
    args.push(Box::new(os_context));
    // TODO(AlonH, 21/12/2022): Consider using StarkFelt.
    args.push(Box::new(MaybeRelocatable::Int(bigint!(call_entry_point.calldata.len()))));
    let calldata: Vec<MaybeRelocatable> =
        call_entry_point.calldata.iter().map(|arg| MaybeRelocatable::Int(bigint!(*arg))).collect();
    args.push(Box::new(calldata));

    cairo_runner.run_from_entrypoint(
        entry_point_pc,
        args.iter().map(|x| x.as_ref()).collect(),
        false,
        true,
        true,
        &mut vm,
        hint_executor,
    )?;

    get_return_values(&vm)
}

fn get_return_values(vm: &VirtualMachine) -> Result<Vec<BigInt>> {
    let [ret_data_size, ret_data_ptr]: [MaybeRelocatable; 2] = vm
        .get_return_values(2)?
        .try_into()
        .unwrap_or_else(|_| panic!("Return values should be of size 2."));
    // Convert ret_data_size from MaybeRelocatable to BigInt.
    let ret_data_size = match ret_data_size {
        MaybeRelocatable::Int(ret_data_size) => ret_data_size,
        relocatable => bail!(VirtualMachineError::ExpectedInteger(relocatable)),
    };
    // Convert ret_data_size from BigInt to usize.
    // TODO(AlonH, 21/12/2022): Handle case where res_data_size is larger than usize.
    let ret_data_size = ret_data_size.bits() as usize;

    let values = vm.get_range(&ret_data_ptr, ret_data_size)?;
    // Extract BigInt values.
    let values: Result<Vec<BigInt>> = values
        .into_iter()
        .map(|x| x.as_deref().cloned())
        .map(|x| match x {
            Some(MaybeRelocatable::Int(value)) => Ok(value),
            Some(relocatable) => bail!(VirtualMachineError::ExpectedInteger(relocatable)),
            None => bail!(VirtualMachineError::NoneInMemoryRange),
        })
        .collect();
    values
}
