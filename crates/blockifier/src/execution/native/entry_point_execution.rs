use cairo_lang_sierra::program::Program as SierraProgram;
use cairo_lang_starknet_classes::contract_class::ContractEntryPoints;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;

use super::syscall_handler::NativeSyscallHandler;
use super::utils::{get_sierra_entry_function_id, match_entrypoint, run_native_executor};
use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::NativeContractClassV1;
use crate::execution::entry_point::{
    CallEntryPoint, EntryPointExecutionContext, EntryPointExecutionResult,
};
use crate::state::state_api::State;

pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: NativeContractClassV1,
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
) -> EntryPointExecutionResult<CallInfo> {
    let sierra_program: &SierraProgram = &contract_class.sierra_program;
    let contract_entrypoints: &ContractEntryPoints = &contract_class.entry_points_by_type;

    let matching_entrypoint =
        match_entrypoint(call.entry_point_type, call.entry_point_selector, contract_entrypoints)?;

    let syscall_handler: NativeSyscallHandler<'_> = NativeSyscallHandler::new(
        state,
        call.caller_address,
        call.storage_address,
        call.entry_point_selector,
        resources,
        context,
    );

    let sierra_entry_function_id =
        get_sierra_entry_function_id(matching_entrypoint, sierra_program);

    println!("Blockifier-Native: running the Native Executor");
    let result = run_native_executor(
        &contract_class.executor,
        sierra_entry_function_id,
        call,
        syscall_handler,
    );
    println!("Blockifier-Native: Native Executor finished running");
    result
}
