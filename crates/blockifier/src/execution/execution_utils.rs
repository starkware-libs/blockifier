use std::collections::HashMap;

use cairo_felt::Felt252;
use cairo_vm::serde::deserialize_program::{
    deserialize_array_of_bigint_hex, deserialize_felt_hex, Attribute, HintParams, Identifier,
    ReferenceManager,
};
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::runners::cairo_runner::{CairoArg, CairoRunner};
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::Calldata;

use crate::block_context::BlockContext;
use crate::execution::entry_point::{
    execute_constructor_entry_point, CallEntryPoint, CallExecution, CallInfo,
    EntryPointExecutionResult, ExecutionContext, Retdata,
};
use crate::execution::errors::{
    PostExecutionError, PreExecutionError, VirtualMachineExecutionError,
};
use crate::execution::syscall_handling::{execute_inner_call, SyscallHintProcessor};
use crate::execution::syscalls::SyscallResult;
use crate::state::state_api::State;
use crate::transaction::objects::AccountTransactionContext;

pub type Args = Vec<CairoArg>;

#[cfg(test)]
#[path = "execution_utils_test.rs"]
pub mod test;

pub struct VmExecutionContext<'a> {
    pub runner: CairoRunner,
    pub vm: VirtualMachine,
    pub syscall_handler: SyscallHintProcessor<'a>,
    pub initial_syscall_ptr: Relocatable,
    pub entry_point_pc: usize,
}

pub fn stark_felt_to_felt(stark_felt: StarkFelt) -> Felt252 {
    Felt252::from_bytes_be(stark_felt.bytes())
}

pub fn felt_to_stark_felt(felt: &Felt252) -> StarkFelt {
    let biguint = format!("{:#x}", felt.to_biguint());
    StarkFelt::try_from(biguint.as_str()).expect("Felt252 must be in StarkFelt's range.")
}

pub fn initialize_execution_context<'a>(
    call: &CallEntryPoint,
    class_hash: ClassHash,
    state: &'a mut dyn State,
    execution_context: &'a mut ExecutionContext,
    block_context: &'a BlockContext,
    account_tx_context: &'a AccountTransactionContext,
) -> Result<VmExecutionContext<'a>, PreExecutionError> {
    let contract_class = state.get_contract_class(&class_hash)?;

    // Resolve initial PC from EP indicator.
    let entry_point_pc = call.resolve_entry_point_pc(&contract_class)?;

    // Instantiate Cairo runner.
    let program = convert_program_to_cairo_runner_format(&contract_class.program)?;
    let proof_mode = false;
    let mut runner = CairoRunner::new(&program, "all", proof_mode)?;

    let trace_enabled = true;
    let mut vm = VirtualMachine::new(trace_enabled);

    runner.initialize_builtins(&mut vm)?;
    runner.initialize_segments(&mut vm, None);

    // Instantiate syscall handler.
    let initial_syscall_ptr = vm.add_memory_segment();
    let syscall_handler = SyscallHintProcessor::new(
        state,
        execution_context,
        block_context,
        account_tx_context,
        initial_syscall_ptr,
        call.storage_address,
        call.caller_address,
    );

    Ok(VmExecutionContext { runner, vm, syscall_handler, initial_syscall_ptr, entry_point_pc })
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
        vm.get_builtin_runners()
            .iter()
            .flat_map(|(_name, builtin_runner)| builtin_runner.initial_stack()),
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

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_entry_point_call(
    call: CallEntryPoint,
    class_hash: ClassHash,
    state: &mut dyn State,
    execution_context: &mut ExecutionContext,
    block_context: &BlockContext,
    account_tx_context: &AccountTransactionContext,
) -> EntryPointExecutionResult<CallInfo> {
    let vm_execution_context = initialize_execution_context(
        &call,
        class_hash,
        state,
        execution_context,
        block_context,
        account_tx_context,
    )?;
    let mut vm = vm_execution_context.vm;
    let mut runner = vm_execution_context.runner;
    let mut syscall_handler = vm_execution_context.syscall_handler;

    let (implicit_args, args) = prepare_call_arguments(
        &call,
        &mut vm,
        vm_execution_context.initial_syscall_ptr,
        &mut syscall_handler.read_only_segments,
    )?;
    let n_total_args = args.len();

    run_entry_point(
        &mut runner,
        &mut vm,
        vm_execution_context.entry_point_pc,
        args,
        &mut syscall_handler,
    )?;

    Ok(finalize_execution(vm, runner, call, syscall_handler, implicit_args, n_total_args)?)
}

pub fn run_entry_point(
    runner: &mut CairoRunner,
    vm: &mut VirtualMachine,
    entry_point_pc: usize,
    args: Args,
    hint_processor: &mut SyscallHintProcessor<'_>,
) -> Result<(), VirtualMachineExecutionError> {
    let verify_secure = true;
    let args: Vec<&CairoArg> = args.iter().collect();

    runner.run_from_entrypoint(entry_point_pc, &args, verify_secure, vm, hint_processor)?;

    Ok(())
}

pub fn finalize_execution(
    mut vm: VirtualMachine,
    runner: CairoRunner,
    call: CallEntryPoint,
    syscall_handler: SyscallHintProcessor<'_>,
    implicit_args: Vec<MaybeRelocatable>,
    n_total_args: usize,
) -> Result<CallInfo, PostExecutionError> {
    // The arguments and RO segments are touched by the OS and should not be counted as
    // holes, mark them as accessed.
    let initial_fp = runner
        .get_initial_fp()
        .expect("The initial_fp field should be initialized after running the entry point.");
    // When execution starts the stack holds the EP arguments + [ret_fp, ret_pc].
    let args_ptr = (initial_fp - (n_total_args + 2))?;
    vm.mark_address_range_as_accessed(args_ptr, n_total_args)?;

    let [retdata_size, retdata_ptr]: [MaybeRelocatable; 2] =
        vm.get_return_values(2)?.try_into().expect("Return values must be of size 2.");
    let implicit_args_end_ptr = (vm.get_ap() - 2)?;
    validate_run(&mut vm, runner, implicit_args, implicit_args_end_ptr, &syscall_handler)?;
    syscall_handler.read_only_segments.mark_as_accessed(&mut vm)?;

    Ok(CallInfo {
        call,
        execution: CallExecution {
            retdata: read_execution_retdata(vm, retdata_size, retdata_ptr)?,
            events: syscall_handler.events,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
        },
        inner_calls: syscall_handler.inner_calls,
        storage_read_values: syscall_handler.read_values,
        accessed_storage_keys: syscall_handler.accessed_keys,
    })
}

pub fn validate_run(
    vm: &mut VirtualMachine,
    runner: CairoRunner,
    implicit_args: Vec<MaybeRelocatable>,
    implicit_args_end: Relocatable,
    syscall_handler: &SyscallHintProcessor<'_>,
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

fn read_execution_retdata(
    vm: VirtualMachine,
    retdata_size: MaybeRelocatable,
    retdata_ptr: MaybeRelocatable,
) -> Result<Retdata, PostExecutionError> {
    let retdata_size = match retdata_size {
        MaybeRelocatable::Int(retdata_size) => retdata_size.bits() as usize,
        relocatable => {
            return Err(VirtualMachineError::ExpectedIntAtRange(Some(relocatable)).into());
        }
    };

    Ok(Retdata(felt_range_from_ptr(&vm, Relocatable::try_from(&retdata_ptr)?, retdata_size)?))
}

pub fn felt_from_ptr(
    vm: &VirtualMachine,
    ptr: Relocatable,
) -> Result<StarkFelt, VirtualMachineError> {
    Ok(felt_to_stark_felt(vm.get_integer(ptr)?.as_ref()))
}

pub fn felt_range_from_ptr(
    vm: &VirtualMachine,
    ptr: Relocatable,
    size: usize,
) -> Result<Vec<StarkFelt>, VirtualMachineError> {
    let values = vm.get_integer_range(ptr, size)?;
    // Extract values as `StarkFelt`.
    let values = values.into_iter().map(|felt| felt_to_stark_felt(&felt)).collect();
    Ok(values)
}

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
        builtins: serde_json::from_value(program.builtins)?,
        prime: deserialize_felt_hex(program.prime)?.to_string(),
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

#[derive(Debug)]
// Invariant: read-only.
pub struct ReadOnlySegment {
    pub start_ptr: Relocatable,
    pub length: usize,
}

/// Represents read-only segments dynamically allocated during execution.
#[derive(Debug, Default)]
// Invariant: read-only.
pub struct ReadOnlySegments(Vec<ReadOnlySegment>);

impl ReadOnlySegments {
    pub fn allocate(
        &mut self,
        vm: &mut VirtualMachine,
        data: &Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, MemoryError> {
        let start_ptr = vm.add_memory_segment();
        self.0.push(ReadOnlySegment { start_ptr, length: data.len() });
        vm.load_data(start_ptr, data)?;
        Ok(start_ptr)
    }

    pub fn validate(&self, vm: &mut VirtualMachine) -> Result<(), PostExecutionError> {
        for segment in &self.0 {
            let used_size = vm
                .get_segment_used_size(segment.start_ptr.segment_index as usize)
                .expect("Segments must contain the allocated read-only segment.");
            if segment.length != used_size {
                return Err(PostExecutionError::SecurityValidationError(
                    "Read-only segments".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn mark_as_accessed(self, vm: &mut VirtualMachine) -> Result<(), PostExecutionError> {
        for segment in self.0 {
            vm.mark_address_range_as_accessed(segment.start_ptr, segment.length)?;
        }

        Ok(())
    }
}

/// Instantiates the given class and assigns it an address.
/// Returns the call info of the deployed class' constructor execution.
#[allow(clippy::too_many_arguments)]
pub fn execute_deployment(
    state: &mut dyn State,
    execution_context: &mut ExecutionContext,
    block_context: &BlockContext,
    account_tx_context: &AccountTransactionContext,
    class_hash: ClassHash,
    deployed_contract_address: ContractAddress,
    deployer_address: ContractAddress,
    constructor_calldata: Calldata,
) -> EntryPointExecutionResult<CallInfo> {
    // Address allocation in the state is done before calling the constructor, so that it is
    // visible from it.
    state.set_class_hash_at(deployed_contract_address, class_hash)?;
    execute_constructor_entry_point(
        state,
        execution_context,
        block_context,
        account_tx_context,
        class_hash,
        deployed_contract_address,
        deployer_address,
        constructor_calldata,
    )
}

pub fn execute_library_call(
    syscall_handler: &mut SyscallHintProcessor<'_>,
    vm: &mut VirtualMachine,
    class_hash: ClassHash,
    call_to_external: bool,
    entry_point_selector: EntryPointSelector,
    calldata: Calldata,
) -> SyscallResult<ReadOnlySegment> {
    let entry_point_type =
        if call_to_external { EntryPointType::External } else { EntryPointType::L1Handler };
    let entry_point = CallEntryPoint {
        class_hash: Some(class_hash),
        entry_point_type,
        entry_point_selector,
        calldata,
        // The call context remains the same in a library call.
        storage_address: syscall_handler.storage_address,
        caller_address: syscall_handler.caller_address,
    };

    execute_inner_call(entry_point, vm, syscall_handler)
}
