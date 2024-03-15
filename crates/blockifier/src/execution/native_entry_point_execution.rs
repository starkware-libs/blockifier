use cairo_lang_sierra::program::Program as SierraProgram;
use cairo_lang_starknet_classes::contract_class::ContractEntryPoints;
use starknet_api::core::ClassHash;

use crate::execution::call_info::CallInfo;
use crate::execution::contract_class::SierraContractClassV1;
use crate::execution::entry_point::{CallEntryPoint, EntryPointExecutionContext};
use crate::execution::native_syscall_handler::NativeSyscallHandler;
use crate::execution::sierra_utils::{
    create_callinfo, get_code_class_hash, get_entrypoints, get_native_aot_program_cache,
    get_native_executor, get_program, get_sierra_entry_function_id, match_entrypoint,
    run_native_executor, setup_syscall_handler, wrap_syscall_handler,
};
use crate::state::state_api::State;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;

use super::entry_point::EntryPointExecutionResult;

pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: SierraContractClassV1,
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
) -> EntryPointExecutionResult<CallInfo> {
    let sierra_program: &SierraProgram = get_program(&contract_class);
    let contract_entrypoints: &ContractEntryPoints = get_entrypoints(&contract_class);

    let matching_entrypoint =
        match_entrypoint(call.entry_point_type, call.entry_point_selector, contract_entrypoints);

    let program_cache = get_native_aot_program_cache();

    let code_class_hash: ClassHash = get_code_class_hash(&call, state);

    let native_executor = get_native_executor(code_class_hash, sierra_program, program_cache);

    let mut syscall_handler: NativeSyscallHandler<'_> = setup_syscall_handler(
        state,
        call.caller_address,
        call.storage_address,
        call.entry_point_selector,
        resources, // TODO, no longer supports clone, do we add it or can we get away with using mut refs
        context,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    let syscall_handler_meta = wrap_syscall_handler(&mut syscall_handler);

    let sierra_entry_function_id =
        get_sierra_entry_function_id(matching_entrypoint, sierra_program);

    let run_result = run_native_executor(
        native_executor,
        sierra_entry_function_id,
        &call,
        &syscall_handler_meta,
    )?;

    create_callinfo(
        call,
        run_result,
        syscall_handler.events,
        syscall_handler.l2_to_l1_messages,
        syscall_handler.inner_calls,
    )
}
