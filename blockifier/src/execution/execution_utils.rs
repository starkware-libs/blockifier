use std::any::Any;
use std::collections::HashMap;

use cairo_rs::bigint;
use cairo_rs::serde::deserialize_program::{
    deserialize_array_of_bigint_hex, deserialize_bigint_hex, Attribute, HintParams, Identifier,
    ReferenceManager,
};
use cairo_rs::types::errors::program_errors::ProgramError;
use cairo_rs::types::program::Program;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::runners::cairo_runner::CairoRunner;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::{BigInt, Sign};
use num_traits::Signed;
use starknet_api::hash::StarkFelt;

use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, EntryPointExecutionResult, Retdata,
};
use crate::execution::errors::{
    PostExecutionError, PreExecutionError, VirtualMachineExecutionError,
};
use crate::execution::syscall_handling::{initialize_syscall_handler, SyscallHintProcessor};
use crate::general_errors::ConversionError;
use crate::state::cached_state::CachedState;
use crate::state::state_reader::StateReader;

#[cfg(test)]
#[path = "execution_utils_test.rs"]
pub mod test;

pub fn felt_to_bigint(felt: StarkFelt) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, felt.bytes())
}

pub fn bigint_to_felt(bigint: &BigInt) -> Result<StarkFelt, ConversionError> {
    // TODO(Adi, 29/11/2022): Make sure lambdaclass always maintain that their bigints' are
    // non-negative.
    if bigint.is_negative() {
        Err(ConversionError::NegativeBigIntToFelt(bigint.clone()))
    } else {
        let bigint_hex = format!("{bigint:#x}");
        Ok(StarkFelt::try_from(bigint_hex.as_str())?)
    }
}

pub struct ExecutionContext<'a, SR: StateReader> {
    pub runner: CairoRunner,
    pub vm: VirtualMachine,
    pub syscall_segment: Relocatable,
    pub syscall_handler: SyscallHintProcessor<'a, SR>,
    pub entry_point_pc: usize,
}

pub fn initialize_execution_context<'a, SR: StateReader>(
    call_entry_point: &CallEntryPoint,
    state: &'a mut CachedState<SR>,
) -> Result<ExecutionContext<'a, SR>, PreExecutionError> {
    let class_hash = call_entry_point.validate_contract_deployed_and_get_class_hash(state)?;
    let contract_class = state.get_contract_class(&class_hash)?;

    // Resolve initial PC from EP indicator.
    let entry_point_pc = call_entry_point.resolve_entry_point_pc(contract_class)?;

    // Instantiate Cairo runner.
    let program = convert_program_to_cairo_runner_format(&contract_class.program)?;
    let mut cairo_runner = CairoRunner::new(&program, "all", false)?;
    let mut vm = VirtualMachine::new(program.prime, false, program.error_message_attributes);
    cairo_runner.initialize_builtins(&mut vm)?;
    cairo_runner.initialize_segments(&mut vm, None);
    let (syscall_segment, syscall_handler) =
        initialize_syscall_handler(&mut vm, state, call_entry_point);

    Ok(ExecutionContext {
        runner: cairo_runner,
        vm,
        syscall_segment,
        syscall_handler,
        entry_point_pc,
    })
}

pub fn prepare_call_arguments(
    call_entry_point: &CallEntryPoint,
    vm: &VirtualMachine,
    syscall_segment: Relocatable,
) -> Vec<Box<dyn Any>> {
    let mut args: Vec<Box<dyn Any>> = Vec::new();
    let entry_point_selector =
        MaybeRelocatable::Int(felt_to_bigint(call_entry_point.entry_point_selector.0));
    args.push(Box::new(entry_point_selector));
    let mut implicit_args = Vec::<MaybeRelocatable>::new();
    implicit_args.push(syscall_segment.into());
    implicit_args.extend(
        vm.get_builtin_runners()
            .iter()
            .flat_map(|(_name, builtin_runner)| builtin_runner.initial_stack()),
    );
    args.push(Box::new(implicit_args));
    // TODO(Adi, 29/11/2022): Remove the '.0' access, once derive-more is used in starknet_api.
    let calldata = &call_entry_point.calldata.0;
    args.push(Box::new(MaybeRelocatable::Int(bigint!(calldata.len()))));
    args.push(Box::new(
        calldata
            .iter()
            .map(|arg| MaybeRelocatable::Int(felt_to_bigint(*arg)))
            .collect::<Vec<MaybeRelocatable>>(),
    ));
    args
}

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_entry_point_call<SR: StateReader>(
    call_entry_point: CallEntryPoint,
    state: &mut CachedState<SR>,
) -> EntryPointExecutionResult<CallInfo> {
    let mut execution_context = initialize_execution_context(&call_entry_point, state)?;
    let args = prepare_call_arguments(
        &call_entry_point,
        &execution_context.vm,
        execution_context.syscall_segment,
    );

    run_entry_point(
        &mut execution_context.runner,
        &mut execution_context.vm,
        execution_context.entry_point_pc,
        args,
        &mut execution_context.syscall_handler,
    )?;

    Ok(finalize_execution(
        execution_context.vm,
        call_entry_point,
        execution_context.syscall_handler,
    )?)
}

pub fn run_entry_point<SR: StateReader>(
    cairo_runner: &mut CairoRunner,
    vm: &mut VirtualMachine,
    entry_point_pc: usize,
    args: Vec<Box<dyn Any>>,
    hint_processor: &mut SyscallHintProcessor<'_, SR>,
) -> Result<(), VirtualMachineExecutionError> {
    cairo_runner.run_from_entrypoint(
        entry_point_pc,
        args.iter().map(|x| x.as_ref()).collect(),
        false,
        true,
        true,
        vm,
        hint_processor,
    )?;
    Ok(())
}

pub fn finalize_execution<SR: StateReader>(
    vm: VirtualMachine,
    call_entry_point: CallEntryPoint,
    syscall_handler: SyscallHintProcessor<'_, SR>,
) -> Result<CallInfo, PostExecutionError> {
    Ok(CallInfo {
        call: call_entry_point,
        execution: CallExecution { retdata: extract_execution_retdata(vm)? },
        inner_calls: syscall_handler.inner_calls,
        events: syscall_handler.events,
        l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
    })
}

fn extract_execution_retdata(vm: VirtualMachine) -> Result<Retdata, PostExecutionError> {
    let [retdata_size, retdata_ptr]: [MaybeRelocatable; 2] = vm
        .get_return_values(2)?
        .try_into()
        .unwrap_or_else(|_| panic!("Return values should be of size 2."));

    let retdata_size = match retdata_size {
        // TODO(AlonH, 21/12/2022): Handle case where res_data_size is larger than usize.
        MaybeRelocatable::Int(retdata_size) => retdata_size.bits() as usize,
        relocatable => return Err(VirtualMachineError::ExpectedInteger(relocatable).into()),
    };

    Ok(Retdata(get_felt_range(&vm, &retdata_ptr, retdata_size)?.into()))
}

pub fn get_felt_range(
    vm: &VirtualMachine,
    ptr: &MaybeRelocatable,
    size: usize,
) -> Result<Vec<StarkFelt>, VirtualMachineError> {
    let values = vm.get_continuous_range(ptr, size)?;
    // Extract values as `StarkFelt`.
    let values: Result<Vec<StarkFelt>, VirtualMachineError> =
        values.into_iter().map(|x| get_felt_from_memory_cell(Some(x))).collect();
    values
}

// TODO(Noa, 01/12/2022): Change this temporary solution.
pub fn convert_program_to_cairo_runner_format(
    program: &starknet_api::state::Program,
) -> Result<Program, ProgramError> {
    let program = program.clone();
    let identifiers = serde_json::from_value::<HashMap<String, Identifier>>(program.identifiers)?;

    let start = match identifiers.get("__main__.__start__") {
        Some(identifier) => identifier.pc,
        None => None,
    };
    let end = match identifiers.get("__main__.__end__") {
        Some(identifier) => identifier.pc,
        None => None,
    };

    Ok(Program {
        builtins: serde_json::from_value::<Vec<String>>(program.builtins)?,
        prime: deserialize_bigint_hex(program.prime)?,
        data: deserialize_array_of_bigint_hex(program.data)?,
        constants: {
            let mut constants = HashMap::new();
            for (key, value) in identifiers.iter() {
                if value.type_.as_deref() == Some("const") {
                    let value = value
                        .value
                        .clone()
                        .ok_or_else(|| ProgramError::ConstWithoutValue(key.to_owned()))?;
                    constants.insert(key.to_owned(), value);
                }
            }

            constants
        },
        main: None,
        start,
        end,
        hints: serde_json::from_value::<HashMap<usize, Vec<HintParams>>>(program.hints)?,
        reference_manager: serde_json::from_value::<ReferenceManager>(program.reference_manager)?,
        identifiers,
        error_message_attributes: serde_json::from_value::<Vec<Attribute>>(program.attributes)?
            .into_iter()
            .filter(|attr| attr.name == "error_message")
            .collect(),
        instruction_locations: None,
    })
}

pub fn get_felt_from_memory_cell(
    memory_cell: Option<MaybeRelocatable>,
) -> Result<StarkFelt, VirtualMachineError> {
    match memory_cell {
        Some(MaybeRelocatable::Int(value)) => {
            // TODO(AlonH, 21/12/2022): Return appropriate error.
            bigint_to_felt(&value).map_err(|_| VirtualMachineError::BigintToUsizeFail)
        }
        Some(relocatable) => Err(VirtualMachineError::ExpectedInteger(relocatable)),
        None => Err(VirtualMachineError::NoneInMemoryRange),
    }
}
