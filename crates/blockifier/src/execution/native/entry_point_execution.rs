use cairo_lang_sierra::program::Program as SierraProgram;
use cairo_lang_starknet_classes::contract_class::ContractEntryPoints;
use cairo_native::cache::ProgramCache;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_api::core::ClassHash;

use super::syscall_handler::NativeSyscallHandler;
use super::utils::{
    get_native_executor, get_sierra_entry_function_id, match_entrypoint, run_native_executor,
};
use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::SierraContractClassV1;
use crate::execution::entry_point::{
    CallEntryPoint, EntryPointExecutionContext, EntryPointExecutionResult,
};
use crate::execution::errors::EntryPointExecutionError;
use crate::state::state_api::State;

pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: SierraContractClassV1,
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
    program_cache: &mut ProgramCache<'_, ClassHash>,
) -> EntryPointExecutionResult<CallInfo> {
    let sierra_program: &SierraProgram = &contract_class.sierra_program;
    let contract_entrypoints: &ContractEntryPoints = &contract_class.entry_points_by_type;

    let matching_entrypoint =
        match_entrypoint(call.entry_point_type, call.entry_point_selector, contract_entrypoints)?;

    let code_class_hash: ClassHash =
        call.class_hash.ok_or(EntryPointExecutionError::NativeExecutionError {
            info: String::from("Class hash was not found"),
        })?;

    let native_executor = get_native_executor(code_class_hash, sierra_program, program_cache);

    let syscall_handler: NativeSyscallHandler<'_, '_> = NativeSyscallHandler::new(
        state,
        call.caller_address,
        call.storage_address,
        call.entry_point_selector,
        resources,
        context,
        program_cache,
    );

    let sierra_entry_function_id =
        get_sierra_entry_function_id(matching_entrypoint, sierra_program);

    run_native_executor(native_executor, sierra_entry_function_id, call, syscall_handler)
}
