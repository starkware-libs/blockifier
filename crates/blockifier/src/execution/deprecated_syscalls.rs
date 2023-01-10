use starknet_api::state::EntryPointType;

use crate::execution::syscalls::{LibraryCallRequest, LibraryCallResponse};

use super::{
    entry_point::CallEntryPoint,
    syscall_handling::{execute_inner_call, SyscallHintProcessor},
    syscalls::SyscallResult,
};

pub fn delegate_call(
    request: LibraryCallRequest,
    syscall_handler: &mut SyscallHintProcessor<'_>,
) -> SyscallResult<LibraryCallResponse> {
    let entry_point = CallEntryPoint {
        class_hash: Some(request.class_hash),
        entry_point_type: EntryPointType::External,
        entry_point_selector: request.function_selector,
        calldata: request.calldata,
        // The call context remains the same in a library call.
        storage_address: syscall_handler.storage_address,
        caller_address: syscall_handler.caller_address,
    };
    let retdata = execute_inner_call(entry_point, syscall_handler)?;

    Ok(LibraryCallResponse { retdata })
}
