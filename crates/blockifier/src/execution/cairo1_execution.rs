use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::runners::cairo_runner::{
    CairoArg, CairoRunner, ExecutionResources as VmExecutionResources,
};
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use super::contract_class::EntryPointV1;
use crate::execution::contract_class::ContractClassV1;
use crate::execution::entry_point::{
    CallEntryPoint, CallExecution, CallInfo, EntryPointExecutionResult, ExecutionContext,
};
use crate::execution::errors::{
    PostExecutionError, PreExecutionError, VirtualMachineExecutionError,
};
use crate::execution::execution_utils::{
    read_execution_retdata, stark_felt_to_felt, write_felt, write_maybe_relocatable, Args,
    ReadOnlySegments,
};
use crate::execution::syscalls::hint_processor::SyscallHintProcessor;
use crate::state::state_api::State;

// TODO(spapini): Try to refactor this file into a StarknetRunner struct.

pub struct VmExecutionContext<'a> {
    pub runner: CairoRunner,
    pub vm: VirtualMachine,
    pub syscall_handler: SyscallHintProcessor<'a>,
    pub initial_syscall_ptr: Relocatable,
    pub entry_point: EntryPointV1,
}

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: ContractClassV1,
    state: &mut dyn State,
    context: &mut ExecutionContext,
) -> EntryPointExecutionResult<CallInfo> {
    let VmExecutionContext {
        mut runner,
        mut vm,
        mut syscall_handler,
        initial_syscall_ptr,
        entry_point,
    } = initialize_execution_context(&call, &contract_class, state, context)?;
    let args = prepare_call_arguments(
        &call,
        &mut vm,
        initial_syscall_ptr,
        &mut syscall_handler.read_only_segments,
        &entry_point,
    )?;
    let n_total_args = args.len();

    // Fix the VM resources, in order to calculate the usage of this run at the end.
    let previous_vm_resources = syscall_handler.context.resources.vm_resources.clone();

    prepare_builtin_costs(&mut vm, &contract_class);

    // Execute.
    run_entry_point(&mut vm, &mut runner, &mut syscall_handler, entry_point, args)?;

    Ok(finalize_execution(vm, runner, syscall_handler, call, previous_vm_resources, n_total_args)?)
}

fn prepare_builtin_costs(vm: &mut VirtualMachine, contract_class: &ContractClassV1) {
    // Create the builtin cost segment, with dummy values.
    let mut builtin_cost_segment = vm.add_memory_segment();
    let builtin_cost_segment_start = builtin_cost_segment;
    // TODO(spapini): put real costs here.
    for _i in 0..20 {
        write_felt(vm, &mut builtin_cost_segment, 0.into()).unwrap();
    }
    // Put a pointer to the builtin cost segment at the end of the program (after the
    // additional `ret` statement).
    let mut ptr = (vm.get_pc() + contract_class.program.data.len()).unwrap();
    // Push a "ret" opcode.
    write_felt(vm, &mut ptr, stark_felt!("0x208b7fff7fff7ffe")).unwrap();
    // Push a pointer to the builtin cost segment.
    write_maybe_relocatable(vm, &mut ptr, builtin_cost_segment_start).unwrap();
}

pub fn initialize_execution_context<'a>(
    call: &CallEntryPoint,
    contract_class: &'a ContractClassV1,
    state: &'a mut dyn State,
    context: &'a mut ExecutionContext,
) -> Result<VmExecutionContext<'a>, PreExecutionError> {
    let entry_point = get_entry_point(call, contract_class)?;

    // Instantiate Cairo runner.
    let proof_mode = false;
    let mut runner = CairoRunner::new(&contract_class.0.program, "starknet", proof_mode)?;

    let trace_enabled = true;
    let mut vm = VirtualMachine::new(trace_enabled);

    runner.initialize_builtins(&mut vm)?;
    runner.initialize_segments(&mut vm, None);

    // Instantiate syscall handler.
    let initial_syscall_ptr = vm.add_memory_segment();
    let syscall_handler = SyscallHintProcessor::new(
        state,
        context,
        initial_syscall_ptr,
        call.storage_address,
        call.caller_address,
        &contract_class.hints,
    );

    Ok(VmExecutionContext { runner, vm, syscall_handler, initial_syscall_ptr, entry_point })
}

pub fn get_entry_point(
    call: &CallEntryPoint,
    contract_class: &ContractClassV1,
) -> Result<EntryPointV1, PreExecutionError> {
    let entry_points_of_same_type = &contract_class.0.entry_points_by_type[&call.entry_point_type];
    let filtered_entry_points: Vec<_> = entry_points_of_same_type
        .iter()
        .filter(|ep| ep.selector == call.entry_point_selector)
        .collect();

    match &filtered_entry_points[..] {
        [] => Err(PreExecutionError::EntryPointNotFound(call.entry_point_selector)),
        [entry_point] => Ok((*entry_point).clone()),
        _ => Err(PreExecutionError::DuplicatedEntryPointSelector {
            selector: call.entry_point_selector,
            typ: call.entry_point_type,
        }),
    }
}

pub fn prepare_call_arguments(
    call: &CallEntryPoint,
    vm: &mut VirtualMachine,
    initial_syscall_ptr: Relocatable,
    read_only_segments: &mut ReadOnlySegments,
    entrypoint: &EntryPointV1,
) -> Result<Args, PreExecutionError> {
    let mut args: Args = vec![];

    // Push builtins.
    for builtin_name in &entrypoint.builtins {
        if let Some(builtin) =
            vm.get_builtin_runners().iter().find(|builtin| builtin.name() == builtin_name)
        {
            args.extend(builtin.initial_stack().into_iter().map(CairoArg::Single));
            continue;
        }
        panic!("Unsupported builtin");
    }
    // TODO(spapini): Use the correct gas counter.
    // Push gas counter.
    args.push(CairoArg::Single(10000000000.into()));
    // Push syscall ptr.
    args.push(CairoArg::Single(initial_syscall_ptr.into()));

    // Prepare calldata arguments.
    let calldata = &call.calldata.0;
    let calldata: Vec<MaybeRelocatable> =
        calldata.iter().map(|&arg| MaybeRelocatable::from(stark_felt_to_felt(arg))).collect();

    let calldata_start_ptr = read_only_segments.allocate(vm, &calldata)?;
    args.push(CairoArg::Single(calldata_start_ptr.into()));
    args.push(CairoArg::Single((calldata_start_ptr + calldata.len()).unwrap().into()));

    Ok(args)
}
/// Runs the runner from the given PC.
pub fn run_entry_point(
    vm: &mut VirtualMachine,
    runner: &mut CairoRunner,
    hint_processor: &mut SyscallHintProcessor<'_>,
    entry_point: EntryPointV1,
    args: Args,
) -> Result<(), VirtualMachineExecutionError> {
    let verify_secure = true;
    let program_segment_size = None; // Infer size from program.
    let args: Vec<&CairoArg> = args.iter().collect();
    runner.run_from_entrypoint(
        entry_point.pc(),
        &args,
        verify_secure,
        program_segment_size,
        vm,
        hint_processor,
    )?;

    Ok(())
}

pub fn finalize_execution(
    mut vm: VirtualMachine,
    runner: CairoRunner,
    syscall_handler: SyscallHintProcessor<'_>,
    call: CallEntryPoint,
    previous_vm_resources: VmExecutionResources,
    n_total_args: usize,
) -> Result<CallInfo, PostExecutionError> {
    // Close memory holes in segments (OS code touches those memory cells, we simulate it).
    let initial_fp = runner
        .get_initial_fp()
        .expect("The initial_fp field should be initialized after running the entry point.");
    // When execution starts the stack holds the EP arguments + [ret_fp, ret_pc].
    let args_ptr = (initial_fp - (n_total_args + 2))?;
    vm.mark_address_range_as_accessed(args_ptr, n_total_args)?;
    syscall_handler.read_only_segments.mark_as_accessed(&mut vm)?;

    // Get retdata.
    let [retdata_start, retdata_end]: [MaybeRelocatable; 2] =
        vm.get_return_values(2)?.try_into().expect("Return values must be of size 2.");
    let retdata_size = retdata_end.sub(&retdata_start).unwrap();

    // Take into account the VM execution resources of the current call, without inner calls.
    // Has to happen after marking holes in segments as accessed.
    let vm_resources_without_inner_calls = runner
        .get_execution_resources(&vm)
        .map_err(VirtualMachineError::TracerError)?
        .filter_unused_builtins();
    syscall_handler.context.resources.vm_resources += &vm_resources_without_inner_calls;

    let full_call_vm_resources =
        &syscall_handler.context.resources.vm_resources - &previous_vm_resources;
    Ok(CallInfo {
        call,
        execution: CallExecution {
            retdata: read_execution_retdata(vm, retdata_size, retdata_start)?,
            events: syscall_handler.events,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
        },
        vm_resources: full_call_vm_resources.filter_unused_builtins(),
        inner_calls: syscall_handler.inner_calls,
        storage_read_values: syscall_handler.read_values,
        accessed_storage_keys: syscall_handler.accessed_keys,
    })
}

pub fn validate_run(
    vm: &mut VirtualMachine,
    runner: &CairoRunner,
    syscall_handler: &SyscallHintProcessor<'_>,
    implicit_args: Vec<MaybeRelocatable>,
    implicit_args_end: Relocatable,
) -> Result<(), PostExecutionError> {
    // Validate builtins' final stack.
    let mut current_builtin_ptr = implicit_args_end;
    current_builtin_ptr = runner.get_builtins_final_stack(vm, current_builtin_ptr)?;

    // Validate implicit arguments segment length is unchanged.
    // Subtract one to get to the first implicit arg segment (the syscall pointer).
    let implicit_args_start = (current_builtin_ptr - 1)?;
    if (implicit_args_start + implicit_args.len())? != implicit_args_end {
        return Err(PostExecutionError::SecurityValidationError(
            "Implicit arguments' segments".to_string(),
        ));
    }

    // Validate syscall segment start.
    let syscall_start_ptr = implicit_args.first().expect("Implicit args must not be empty.");
    let syscall_start_ptr = Relocatable::try_from(syscall_start_ptr)?;
    if syscall_start_ptr.offset != 0 {
        return Err(PostExecutionError::SecurityValidationError(
            "Syscall segment start".to_string(),
        ));
    }

    // Validate syscall segment size.
    let syscall_end_ptr = vm.get_relocatable(implicit_args_start)?;
    let syscall_used_size = vm
        .get_segment_used_size(syscall_start_ptr.segment_index as usize)
        .expect("Segments must contain the syscall segment.");
    if (syscall_start_ptr + syscall_used_size)? != syscall_end_ptr {
        return Err(PostExecutionError::SecurityValidationError(
            "Syscall segment size".to_string(),
        ));
    }

    // Validate syscall segment end.
    syscall_handler.verify_syscall_ptr(syscall_end_ptr).map_err(|_| {
        PostExecutionError::SecurityValidationError("Syscall segment end".to_string())
    })?;

    syscall_handler.read_only_segments.validate(vm)
}
