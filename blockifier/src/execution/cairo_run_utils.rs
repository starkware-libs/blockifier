use std::any::Any;

use anyhow::{bail, Result};
use cairo_rs::bigint;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_rs::types::errors::program_errors::ProgramError::EntrypointNotFound;
use cairo_rs::types::program::Program;
use cairo_rs::types::relocatable::MaybeRelocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::runners::cairo_runner::CairoRunner;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::{BigInt, Sign};
use starknet_api::StarkFelt;

use crate::execution::entry_point::CallEntryPoint;
use crate::execution::syscall_utils::{add_syscall_hints, SyscallHandler};

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

pub fn felt_to_bigint(felt: StarkFelt) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, felt.bytes())
}

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_call_entry_point(
    call_entry_point: &CallEntryPoint,
    config: CairoRunConfig,
) -> Result<Vec<BigInt>> {
    // Instantiate Cairo runner.
    let program =
        Program::from_file(&call_entry_point.contract_file_path, Some(&call_entry_point.name))?;
    let layout: String = config.layout.into();
    let mut cairo_runner = CairoRunner::new(&program, &layout, config.proof_mode)?;
    let mut vm = VirtualMachine::new(program.prime, config.enable_trace);
    cairo_runner.initialize_builtins(&mut vm)?;
    cairo_runner.initialize_segments(&mut vm, None);
    let syscall_segment = vm.add_memory_segment();
    let mut syscall_handler = SyscallHandler::new(syscall_segment.clone());
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    add_syscall_hints(&mut hint_processor, &mut syscall_handler);
    cairo_runner
        .exec_scopes
        .assign_or_update_variable("syscall_handler", Box::new(syscall_handler));

    // Prepare arguments for run.
    let mut args: Vec<Box<dyn Any>> = Vec::new();
    // TODO(AlonH, 21/12/2022): Push the entry point selector to args once it is used.
    // Holds pointers for the syscall handler and for the used builtins, which are all given as
    // implicit arguments to the entry point.
    let mut execution_context = Vec::<MaybeRelocatable>::new();
    execution_context.push(syscall_segment.into());
    execution_context.extend(
        vm.get_builtin_runners()
            .iter()
            .flat_map(|(_name, builtin_runner)| builtin_runner.initial_stack()),
    );
    args.push(Box::new(execution_context));
    // TODO(AlonH, 21/12/2022): Consider using StarkFelt.
    // TODO(Adi, 29/11/2022): Remove the '.0' access, once derive-more is used in starknet_api.
    let calldata = &call_entry_point.calldata.0;
    args.push(Box::new(MaybeRelocatable::Int(bigint!(calldata.len()))));
    args.push(Box::new(
        calldata
            .iter()
            .map(|arg| MaybeRelocatable::Int(felt_to_bigint(*arg)))
            .collect::<Vec<MaybeRelocatable>>(),
    ));

    // Resolve initial PC from EP indicator.
    let entry_point_not_found_error = EntrypointNotFound(call_entry_point.name.clone());
    let entry_point_identifier =
        match program.identifiers.get(&format!("__wrappers__.{}", &call_entry_point.name)) {
            Some(identifier) => identifier,
            None => bail!(entry_point_not_found_error),
        };
    let entry_point_pc = match entry_point_identifier.pc {
        Some(pc) => pc,
        None => bail!(entry_point_not_found_error),
    };

    // Run.
    cairo_runner.run_from_entrypoint(
        entry_point_pc,
        args.iter().map(|x| x.as_ref()).collect(),
        false,
        true,
        true,
        &mut vm,
        &hint_processor,
    )?;

    Ok(extract_execution_return_data(&vm)?)
}

fn extract_execution_return_data(vm: &VirtualMachine) -> Result<Vec<BigInt>, VirtualMachineError> {
    let [return_data_size, return_data_ptr]: [MaybeRelocatable; 2] = vm
        .get_return_values(2)?
        .try_into()
        .unwrap_or_else(|_| panic!("Return values should be of size 2."));

    let return_data_size = match return_data_size {
        // TODO(AlonH, 21/12/2022): Handle case where res_data_size is larger than usize.
        MaybeRelocatable::Int(return_data_size) => return_data_size.bits() as usize,
        relocatable => return Err(VirtualMachineError::ExpectedInteger(relocatable)),
    };

    let values = vm.get_range(&return_data_ptr, return_data_size)?;
    // Extract values as `BigInt`.
    let values: Result<Vec<BigInt>, VirtualMachineError> = values
        .into_iter()
        .map(|x| x.as_deref().cloned())
        .map(get_bigint_from_memory_cell)
        .collect();
    values
}

pub fn get_bigint_from_memory_cell(
    memory_cell: Option<MaybeRelocatable>,
) -> Result<BigInt, VirtualMachineError> {
    match memory_cell {
        Some(MaybeRelocatable::Int(value)) => Ok(value),
        Some(relocatable) => Err(VirtualMachineError::ExpectedInteger(relocatable)),
        None => Err(VirtualMachineError::NoneInMemoryRange),
    }
}
