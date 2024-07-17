use cairo_native::cache::ProgramCache;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources};
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkHash;

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants::{CONSTRUCTOR_ENTRY_POINT_NAME, DEFAULT_ENTRY_POINT_SELECTOR};
use crate::execution::call_info::{CallExecution, CallInfo};
use crate::execution::contract_class::ContractClassV0;
use crate::execution::deprecated_syscalls::hint_processor::DeprecatedSyscallHintProcessor;
use crate::execution::entry_point::{
    CallEntryPoint, EntryPointExecutionContext, EntryPointExecutionResult,
};
use crate::execution::errors::{PostExecutionError, PreExecutionError};
use crate::execution::execution_utils::{
    read_execution_retdata, stark_felt_to_felt, Args, ReadOnlySegments,
};
use crate::state::state_api::State;

pub struct VmExecutionContext<'a, 'context> {
    pub runner: CairoRunner,
    pub vm: VirtualMachine,
    pub syscall_handler: DeprecatedSyscallHintProcessor<'a, 'context>,
    pub initial_syscall_ptr: Relocatable,
    pub entry_point_pc: usize,
}

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: ContractClassV0,
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
    cache: &mut ProgramCache<'_, ClassHash>,
) -> EntryPointExecutionResult<CallInfo> {
    let VmExecutionContext {
        mut runner,
        mut vm,
        mut syscall_handler,
        initial_syscall_ptr,
        entry_point_pc,
    } = initialize_execution_context(&call, contract_class, state, resources, context, cache)?;

    let (implicit_args, args) = prepare_call_arguments(
        &call,
        &mut vm,
        initial_syscall_ptr,
        &mut syscall_handler.read_only_segments,
    )?;
    let n_total_args = args.len();

    // Fix the VM resources, in order to calculate the usage of this run at the end.
    let previous_resources = syscall_handler.resources.clone();

    // Execute.
    run_entry_point(&mut vm, &mut runner, &mut syscall_handler, entry_point_pc, args)?;

    Ok(finalize_execution(
        vm,
        runner,
        syscall_handler,
        call,
        previous_resources,
        implicit_args,
        n_total_args,
    )?)
}

pub fn initialize_execution_context<'a, 'context>(
    call: &CallEntryPoint,
    contract_class: ContractClassV0,
    state: &'a mut dyn State,
    resources: &'a mut ExecutionResources,
    context: &'a mut EntryPointExecutionContext,
    cache: &'a mut ProgramCache<'context, ClassHash>,
) -> Result<VmExecutionContext<'a, 'context>, PreExecutionError> {
    // Resolve initial PC from EP indicator.
    let entry_point_pc = resolve_entry_point_pc(call, &contract_class)?;

    // Instantiate Cairo runner.
    let proof_mode = false;
    let mut runner = CairoRunner::new(&contract_class.program, "starknet", proof_mode)?;

    let trace_enabled = false;
    let mut vm = VirtualMachine::new(trace_enabled);

    runner.initialize_builtins(&mut vm)?;
    runner.initialize_segments(&mut vm, None);

    // Instantiate syscall handler.
    let initial_syscall_ptr = vm.add_memory_segment();
    let syscall_handler = DeprecatedSyscallHintProcessor::new(
        state,
        resources,
        context,
        initial_syscall_ptr,
        call.storage_address,
        call.caller_address,
        cache,
    );

    Ok(VmExecutionContext { runner, vm, syscall_handler, initial_syscall_ptr, entry_point_pc })
}

pub fn resolve_entry_point_pc(
    call: &CallEntryPoint,
    contract_class: &ContractClassV0,
) -> Result<usize, PreExecutionError> {
    if call.entry_point_type == EntryPointType::Constructor
        && call.entry_point_selector != selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME)
    {
        return Err(PreExecutionError::InvalidConstructorEntryPointName);
    }

    let entry_points_of_same_type = &contract_class.entry_points_by_type[&call.entry_point_type];
    let filtered_entry_points: Vec<_> = entry_points_of_same_type
        .iter()
        .filter(|ep| ep.selector == call.entry_point_selector)
        .collect();

    // Returns the default entrypoint if the given selector is missing.
    if filtered_entry_points.is_empty() {
        match entry_points_of_same_type.first() {
            Some(entry_point) => {
                if entry_point.selector
                    == EntryPointSelector(StarkHash::from(DEFAULT_ENTRY_POINT_SELECTOR))
                {
                    return Ok(entry_point.offset.0);
                } else {
                    return Err(PreExecutionError::EntryPointNotFound(call.entry_point_selector));
                }
            }
            None => {
                return Err(PreExecutionError::NoEntryPointOfTypeFound(call.entry_point_type));
            }
        }
    }

    if filtered_entry_points.len() > 1 {
        return Err(PreExecutionError::DuplicatedEntryPointSelector {
            selector: call.entry_point_selector,
            typ: call.entry_point_type,
        });
    }

    // Filtered entry points contain exactly one element.
    let entry_point = filtered_entry_points
        .first()
        .expect("The number of entry points with the given selector is exactly one.");
    Ok(entry_point.offset.0)
}

pub fn prepare_call_arguments(
    call: &CallEntryPoint,
    vm: &mut VirtualMachine,
    initial_syscall_ptr: Relocatable,
    read_only_segments: &mut ReadOnlySegments,
) -> Result<(Vec<MaybeRelocatable>, Args), PreExecutionError> {
    let mut args: Args = vec![];

    // Prepare called EP details.
    let entry_point_selector =
        MaybeRelocatable::from(stark_felt_to_felt(call.entry_point_selector.0));
    args.push(CairoArg::from(entry_point_selector));

    // Prepare implicit arguments.
    let mut implicit_args = vec![];
    implicit_args.push(MaybeRelocatable::from(initial_syscall_ptr));
    implicit_args.extend(
        vm.get_builtin_runners().iter().flat_map(|builtin_runner| builtin_runner.initial_stack()),
    );
    args.push(CairoArg::from(implicit_args.clone()));

    // Prepare calldata arguments.
    let calldata = &call.calldata.0;
    let calldata: Vec<MaybeRelocatable> =
        calldata.iter().map(|&arg| MaybeRelocatable::from(stark_felt_to_felt(arg))).collect();
    let calldata_length = MaybeRelocatable::from(calldata.len());
    args.push(CairoArg::from(calldata_length));

    let calldata_start_ptr = MaybeRelocatable::from(read_only_segments.allocate(vm, &calldata)?);
    args.push(CairoArg::from(calldata_start_ptr));

    Ok((implicit_args, args))
}
/// Runs the runner from the given PC.
pub fn run_entry_point(
    vm: &mut VirtualMachine,
    runner: &mut CairoRunner,
    hint_processor: &mut DeprecatedSyscallHintProcessor<'_, '_>,
    entry_point_pc: usize,
    args: Args,
) -> EntryPointExecutionResult<()> {
    let verify_secure = true;
    let program_segment_size = None; // Infer size from program.
    let args: Vec<&CairoArg> = args.iter().collect();
    let result = runner.run_from_entrypoint(
        entry_point_pc,
        &args,
        verify_secure,
        program_segment_size,
        vm,
        hint_processor,
    );

    Ok(result?)
}

pub fn finalize_execution(
    mut vm: VirtualMachine,
    runner: CairoRunner,
    syscall_handler: DeprecatedSyscallHintProcessor<'_, '_>,
    call: CallEntryPoint,
    previous_resources: ExecutionResources,
    implicit_args: Vec<MaybeRelocatable>,
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

    // Validate run.
    let [retdata_size, retdata_ptr]: [MaybeRelocatable; 2] =
        vm.get_return_values(2)?.try_into().expect("Return values must be of size 2.");
    let implicit_args_end_ptr = (vm.get_ap() - 2)?;
    validate_run(&mut vm, &runner, &syscall_handler, implicit_args, implicit_args_end_ptr)?;

    // Take into account the VM execution resources of the current call, without inner calls.
    // Has to happen after marking holes in segments as accessed.
    let vm_resources_without_inner_calls = runner
        .get_execution_resources(&vm)
        .map_err(VirtualMachineError::RunnerError)?
        .filter_unused_builtins();
    *syscall_handler.resources += &vm_resources_without_inner_calls;
    let versioned_constants = syscall_handler.context.versioned_constants();
    // Take into account the syscall resources of the current call.
    *syscall_handler.resources += &versioned_constants
        .get_additional_os_syscall_resources(&syscall_handler.syscall_counter)?;

    let full_call_resources = &*syscall_handler.resources - &previous_resources;
    Ok(CallInfo {
        call,
        execution: CallExecution {
            retdata: read_execution_retdata(&vm, retdata_size, &retdata_ptr)?,
            events: syscall_handler.events,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
            failed: false,
            gas_consumed: 0,
        },
        resources: full_call_resources.filter_unused_builtins(),
        inner_calls: syscall_handler.inner_calls,
        storage_read_values: syscall_handler.read_values,
        accessed_storage_keys: syscall_handler.accessed_keys,
    })
}

pub fn validate_run(
    vm: &mut VirtualMachine,
    runner: &CairoRunner,
    syscall_handler: &DeprecatedSyscallHintProcessor<'_, '_>,
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
        .get_segment_used_size(
            syscall_start_ptr
                .segment_index
                .try_into()
                .expect("The size of isize and usize should be the same."),
        )
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
