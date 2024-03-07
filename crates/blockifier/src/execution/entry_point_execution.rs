use std::collections::HashSet;

use cairo_felt::Felt252;
use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources};
use cairo_vm::vm::vm_core::VirtualMachine;
use num_traits::ToPrimitive;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::execution::call_info::{CallExecution, CallInfo, Retdata};
use crate::execution::contract_class::{ContractClassV1, EntryPointV1};
use crate::execution::entry_point::{
    CallEntryPoint, EntryPointExecutionContext, EntryPointExecutionResult,
};
use crate::execution::errors::{EntryPointExecutionError, PostExecutionError, PreExecutionError};
use crate::execution::execution_utils::{
    read_execution_retdata, stark_felt_to_felt, write_maybe_relocatable, write_stark_felt, Args,
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
    // Additional data required for execution is appended after the program bytecode.
    pub program_extra_data_length: usize,
}

pub struct CallResult {
    pub failed: bool,
    pub retdata: Retdata,
    pub gas_consumed: u64,
}

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: ContractClassV1,
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
) -> EntryPointExecutionResult<CallInfo> {
    // println!("Executing via vm");
    // Fetch the class hash from `call`.
    let class_hash = call.class_hash.ok_or(EntryPointExecutionError::InternalError(
        "Class hash must not be None when executing an entry point.".into(),
    ))?;

    let VmExecutionContext {
        mut runner,
        mut vm,
        mut syscall_handler,
        initial_syscall_ptr,
        entry_point,
        program_extra_data_length,
    } = initialize_execution_context(call, &contract_class, state, resources, context)?;

    let args = prepare_call_arguments(
        &syscall_handler.call,
        &mut vm,
        initial_syscall_ptr,
        &mut syscall_handler.read_only_segments,
        &entry_point,
    )?;
    let n_total_args = args.len();

    // Fix the resources, in order to calculate the usage of this run at the end.
    let previous_resources = syscall_handler.resources.clone();

    // Execute.
    let bytecode_length = contract_class.bytecode_length();
    let program_segment_size = bytecode_length + program_extra_data_length;
    run_entry_point(
        &mut vm,
        &mut runner,
        &mut syscall_handler,
        entry_point,
        args,
        program_segment_size,
    )?;

    // Collect the set PC values that were visited during the entry point execution.
    register_visited_pcs(
        &mut vm,
        syscall_handler.state,
        class_hash,
        program_segment_size,
        bytecode_length,
    )?;

    let call_info = finalize_execution(
        vm,
        runner,
        syscall_handler,
        previous_resources,
        n_total_args,
        program_extra_data_length,
    )?;
    if call_info.execution.failed {
        return Err(EntryPointExecutionError::ExecutionFailed {
            error_data: call_info.execution.retdata.0,
        });
    }

    Ok(call_info)
}

// Collects the set PC values that were visited during the entry point execution.
fn register_visited_pcs(
    vm: &mut VirtualMachine,
    state: &mut dyn State,
    class_hash: starknet_api::core::ClassHash,
    program_segment_size: usize,
    bytecode_length: usize,
) -> EntryPointExecutionResult<()> {
    let mut class_visited_pcs = HashSet::new();
    // Relocate the trace, putting the program segment at address 1 and the execution segment right
    // after it.
    // TODO(lior): Avoid unnecessary relocation once the VM has a non-relocated `get_trace()`
    //   function.
    vm.relocate_trace(&[1, 1 + program_segment_size])?;
    for trace_entry in vm.get_relocated_trace()? {
        let pc = trace_entry.pc;
        if pc < 1 {
            return Err(EntryPointExecutionError::InternalError(format!(
                "Invalid PC value {pc} in trace."
            )));
        }
        let real_pc = pc - 1;
        // Jumping to a PC that is not inside the bytecode is possible. For example, to obtain
        // the builtin costs. Filter out these values.
        if real_pc < bytecode_length {
            class_visited_pcs.insert(real_pc);
        }
    }
    state.add_visited_pcs(class_hash, &class_visited_pcs);
    Ok(())
}

pub fn initialize_execution_context<'a>(
    call: CallEntryPoint,
    contract_class: &'a ContractClassV1,
    state: &'a mut dyn State,
    resources: &'a mut ExecutionResources,
    context: &'a mut EntryPointExecutionContext,
) -> Result<VmExecutionContext<'a>, PreExecutionError> {
    let entry_point = contract_class.get_entry_point(&call)?;

    // Instantiate Cairo runner.
    let proof_mode = false;
    let mut runner = CairoRunner::new(&contract_class.0.program, "starknet", proof_mode)?;

    let trace_enabled = true;
    let mut vm = VirtualMachine::new(trace_enabled);

    // Initialize program with all builtins.
    let program_builtins = [
        BuiltinName::bitwise,
        BuiltinName::ec_op,
        BuiltinName::ecdsa,
        BuiltinName::output,
        BuiltinName::pedersen,
        BuiltinName::poseidon,
        BuiltinName::range_check,
        BuiltinName::segment_arena,
    ];
    runner.initialize_function_runner_cairo_1(&mut vm, &program_builtins)?;
    let mut read_only_segments = ReadOnlySegments::default();
    let program_extra_data_length =
        prepare_program_extra_data(&mut vm, contract_class, &mut read_only_segments)?;

    // Instantiate syscall handler.
    let initial_syscall_ptr = vm.add_memory_segment();
    let syscall_handler = SyscallHintProcessor::new(
        state,
        resources,
        context,
        initial_syscall_ptr,
        call,
        &contract_class.hints,
        read_only_segments,
    );

    Ok(VmExecutionContext {
        runner,
        vm,
        syscall_handler,
        initial_syscall_ptr,
        entry_point,
        program_extra_data_length,
    })
}

fn prepare_program_extra_data(
    vm: &mut VirtualMachine,
    contract_class: &ContractClassV1,
    read_only_segments: &mut ReadOnlySegments,
) -> Result<usize, PreExecutionError> {
    // Create the builtin cost segment, with dummy values.
    let mut data = vec![];

    // TODO(spapini): Put real costs here.
    for _i in 0..20 {
        data.push(MaybeRelocatable::from(0));
    }
    let builtin_cost_segment_start = read_only_segments.allocate(vm, &data)?;

    // Put a pointer to the builtin cost segment at the end of the program (after the
    // additional `ret` statement).
    let mut ptr = (vm.get_pc() + contract_class.bytecode_length())?;
    // Push a `ret` opcode.
    write_stark_felt(vm, &mut ptr, stark_felt!("0x208b7fff7fff7ffe"))?;
    // Push a pointer to the builtin cost segment.
    write_maybe_relocatable(vm, &mut ptr, builtin_cost_segment_start)?;

    let program_extra_data_length = 2;
    Ok(program_extra_data_length)
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
        if builtin_name == SEGMENT_ARENA_BUILTIN_NAME {
            let segment_arena = vm.add_memory_segment();

            // Write into segment_arena.
            let mut ptr = segment_arena;
            let info_segment = vm.add_memory_segment();
            let n_constructed = StarkFelt::default();
            let n_destructed = StarkFelt::default();
            write_maybe_relocatable(vm, &mut ptr, info_segment)?;
            write_stark_felt(vm, &mut ptr, n_constructed)?;
            write_stark_felt(vm, &mut ptr, n_destructed)?;

            args.push(CairoArg::Single(MaybeRelocatable::from(ptr)));
            continue;
        }
        return Err(PreExecutionError::InvalidBuiltin(builtin_name.clone()));
    }
    // Push gas counter.
    args.push(CairoArg::Single(MaybeRelocatable::from(Felt252::from(call.initial_gas))));
    // Push syscall ptr.
    args.push(CairoArg::Single(MaybeRelocatable::from(initial_syscall_ptr)));

    // Prepare calldata arguments.
    let calldata = &call.calldata.0;
    let calldata: Vec<MaybeRelocatable> =
        calldata.iter().map(|&arg| MaybeRelocatable::from(stark_felt_to_felt(arg))).collect();

    let calldata_start_ptr = read_only_segments.allocate(vm, &calldata)?;
    let calldata_end_ptr = MaybeRelocatable::from((calldata_start_ptr + calldata.len())?);
    args.push(CairoArg::Single(MaybeRelocatable::from(calldata_start_ptr)));
    args.push(CairoArg::Single(calldata_end_ptr));

    Ok(args)
}
/// Runs the runner from the given PC.
pub fn run_entry_point(
    vm: &mut VirtualMachine,
    runner: &mut CairoRunner,
    hint_processor: &mut SyscallHintProcessor<'_>,
    entry_point: EntryPointV1,
    args: Args,
    program_segment_size: usize,
) -> EntryPointExecutionResult<()> {
    let verify_secure = true;
    let args: Vec<&CairoArg> = args.iter().collect();
    let result = runner.run_from_entrypoint(
        entry_point.pc(),
        &args,
        verify_secure,
        Some(program_segment_size),
        vm,
        hint_processor,
    );

    Ok(result?)
}

pub fn finalize_execution(
    mut vm: VirtualMachine,
    runner: CairoRunner,
    syscall_handler: SyscallHintProcessor<'_>,
    previous_resources: ExecutionResources,
    n_total_args: usize,
    program_extra_data_length: usize,
) -> Result<CallInfo, PostExecutionError> {
    // Close memory holes in segments (OS code touches those memory cells, we simulate it).
    let program_start_ptr = runner
        .program_base
        .expect("The `program_base` field should be initialized after running the entry point.");
    let program_end_ptr = (program_start_ptr + runner.get_program().data_len())?;
    vm.mark_address_range_as_accessed(program_end_ptr, program_extra_data_length)?;

    let initial_fp = runner
        .get_initial_fp()
        .expect("The `initial_fp` field should be initialized after running the entry point.");
    // When execution starts the stack holds the EP arguments + [ret_fp, ret_pc].
    let args_ptr = (initial_fp - (n_total_args + 2))?;
    vm.mark_address_range_as_accessed(args_ptr, n_total_args)?;
    syscall_handler.read_only_segments.mark_as_accessed(&mut vm)?;

    let call_result = get_call_result(&vm, &syscall_handler)?;

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
        call: syscall_handler.call,
        execution: CallExecution {
            retdata: call_result.retdata,
            events: syscall_handler.events,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
            failed: call_result.failed,
            gas_consumed: call_result.gas_consumed,
        },
        resources: full_call_resources.filter_unused_builtins(),
        inner_calls: syscall_handler.inner_calls,
        storage_read_values: syscall_handler.read_values,
        accessed_storage_keys: syscall_handler.accessed_keys,
    })
}

fn get_call_result(
    vm: &VirtualMachine,
    syscall_handler: &SyscallHintProcessor<'_>,
) -> Result<CallResult, PostExecutionError> {
    let return_result = vm.get_return_values(5)?;
    // Corresponds to the Cairo 1.0 enum:
    // enum PanicResult<Array::<felt>> { Ok: Array::<felt>, Err: Array::<felt>, }.
    let [failure_flag, retdata_start, retdata_end]: &[MaybeRelocatable; 3] =
        (&return_result[2..]).try_into().expect("Return values must be of size 3.");

    let failed = if *failure_flag == MaybeRelocatable::from(0) {
        false
    } else if *failure_flag == MaybeRelocatable::from(1) {
        true
    } else {
        return Err(PostExecutionError::MalformedReturnData {
            error_message: "Failure flag expected to be either 0 or 1.".to_string(),
        });
    };

    let retdata_size = retdata_end.sub(retdata_start)?;
    // TODO(spapini): Validate implicits.

    let gas = &return_result[0];
    let MaybeRelocatable::Int(gas) = gas else {
        return Err(PostExecutionError::MalformedReturnData {
            error_message: "Error extracting return data.".to_string(),
        });
    };
    let gas = gas.to_u64().ok_or(PostExecutionError::MalformedReturnData {
        error_message: format!("Unexpected remaining gas: {gas}."),
    })?;

    if gas > syscall_handler.call.initial_gas {
        return Err(PostExecutionError::MalformedReturnData {
            error_message: format!("Unexpected remaining gas: {gas}."),
        });
    }

    let gas_consumed = syscall_handler.call.initial_gas - gas;
    Ok(CallResult {
        failed,
        retdata: read_execution_retdata(vm, retdata_size, retdata_start)?,
        gas_consumed,
    })
}
