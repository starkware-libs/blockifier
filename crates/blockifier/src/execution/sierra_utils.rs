use std::{cell::RefCell, rc::Rc, collections::{HashMap, HashSet}};

use cairo_lang_sierra::{program::Program as SierraProgram, ids::FunctionId};
use cairo_lang_starknet::contract_class::{ContractEntryPoints, ContractEntryPoint};
use cairo_native::{executor::NativeExecutor, execution_result::ContractExecutionResult, metadata::syscall_handler::SyscallHandlerMeta, cache::{AotProgramCache, ProgramCache}, context::NativeContext};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::Itertools;
use starknet_api::{deprecated_contract_class::EntryPointType, core::{EntryPointSelector, ClassHash, ContractAddress}, hash::StarkFelt};
use starknet_types_core::felt::Felt;

use crate::state::state_api::State;

use super::{contract_class::SierraContractClassV1, call_info::{CallInfo, CallExecution, Retdata}, entry_point::CallEntryPoint, native_syscall_handler::NativeSyscallHandler};

pub fn get_program(contract_class: &SierraContractClassV1) -> &SierraProgram {
    &contract_class.sierra_program
}

pub fn get_entrypoints(contract_class: &SierraContractClassV1) -> &ContractEntryPoints {
    &contract_class.entrypoints_by_type
}

pub fn match_entrypoint(entry_point_type: EntryPointType, entrypoint_selector: EntryPointSelector, contract_entrypoints: &ContractEntryPoints) -> &ContractEntryPoint {
    match entry_point_type {
        EntryPointType::Constructor => todo!("Sierra util: match_entrypoint - constructor"),
        EntryPointType::External => contract_entrypoints
            .external
            .iter()
            .find(|entrypoint| cmp_selector_to_entrypoint(entrypoint_selector, &entrypoint))
            .expect("entrypoint not found"),
        EntryPointType::L1Handler => todo!("Sierra util: match_entrypoint - l1 handler"),
    }
}

fn cmp_selector_to_entrypoint(selector: EntryPointSelector, contract_entrypoint: &ContractEntryPoint) -> bool {
    let entrypoint_selector_str = contract_entrypoint.selector.to_str_radix(16);
    let padded_selector_str = format!("0x{}{}", "0".repeat(64 - entrypoint_selector_str.len()), entrypoint_selector_str);
    selector.0.to_string() == padded_selector_str
}

static NATIVE_CONTEXT: std::sync::OnceLock<cairo_native::context::NativeContext> = std::sync::OnceLock::new();

// StarkHash parameter is the class hash type
pub fn get_program_cache<'context>() -> Rc<RefCell<ProgramCache<'context, ClassHash>>> {
    Rc::new(RefCell::new(ProgramCache::Aot(AotProgramCache::new(
        NATIVE_CONTEXT.get_or_init(NativeContext::new)
    ))))
}

pub fn get_code_class_hash(call: &CallEntryPoint, _state: &mut dyn State) -> ClassHash {
    //TODO investigate how this works for delegate calls, and whether this is already handled by the blockifier (rendering this function inlinable)
    call.class_hash.unwrap()
}

pub fn get_native_executor<'context>(class_hash: ClassHash, program: &SierraProgram, program_cache: Rc<RefCell<ProgramCache<'context, ClassHash>>>) -> NativeExecutor<'context> {
    let ref mut program_cache = *program_cache.borrow_mut();
    match program_cache {
        ProgramCache::Aot(cache) => {
            let cached_executor = cache.get(&class_hash);
            NativeExecutor::Aot(match cached_executor {
                Some(executor) => executor,
                None => cache.compile_and_insert(class_hash, program),
            })
        }
        ProgramCache::Jit(_) => todo!("Sierra util: get native executor - jit"),
    }
}

pub fn get_sierra_entry_function_id<'a>(matching_entrypoint: &'a ContractEntryPoint, sierra_program: &'a SierraProgram) -> &'a FunctionId {
    &sierra_program
        .funcs
        .iter()
        .find(|func| func.id.id == matching_entrypoint.function_idx as u64)
        .unwrap()
        .id
}

pub fn setup_syscall_handler<'state>(state: &'state mut dyn State, storage_address: ContractAddress) -> NativeSyscallHandler<'state> {
    NativeSyscallHandler {
        state,
        storage_address,
    }
}

pub fn wrap_syscall_handler<'state>(syscall_handler: &mut NativeSyscallHandler<'state>) -> SyscallHandlerMeta {
    SyscallHandlerMeta::new(syscall_handler)
}

pub fn starkfelt_to_felt(starkfelt: StarkFelt) -> Felt {
    Felt::from_hex(&starkfelt.to_string()).unwrap()
}

pub fn felt_to_starkfelt(felt: Felt) -> StarkFelt {
    StarkFelt::try_from(felt.to_hex_string().as_str()).unwrap()
}

fn starkfelts_to_felts(data: &Vec<StarkFelt>) -> Vec<Felt> {
    data
        .iter()
        .map(|starkfelt| starkfelt_to_felt(*starkfelt))
        .collect_vec()
}

pub fn run_native_executor<'context>(
    native_executor: NativeExecutor<'context>,
    sierra_entry_function_id: &FunctionId,
    call: &CallEntryPoint,
    syscall_handler: &SyscallHandlerMeta
) -> ContractExecutionResult {
    match native_executor {
        NativeExecutor::Aot(executor) => {
            executor.invoke_contract_dynamic(
                sierra_entry_function_id,
                &starkfelts_to_felts(&call.calldata.0),
                Some(call.initial_gas as u128), //TODO track gas reduction?
                Some(syscall_handler)
            ).expect("Native execution error")
        },
        NativeExecutor::Jit(_) => todo!("Jit"),
    }
}

pub fn create_callinfo(call: CallEntryPoint, run_result: ContractExecutionResult) -> Result<CallInfo, super::errors::EntryPointExecutionError> {
    Ok(CallInfo {
        call,
        execution: CallExecution {
            retdata: Retdata(run_result.return_values.into_iter().map(felt_to_starkfelt).collect_vec()),
            events: vec![],
            l2_to_l1_messages: vec![],
            failed: run_result.failure_flag,
            gas_consumed: 34650, // TODO use cairo native's gas logic
        },
        vm_resources: ExecutionResources {
            n_steps: 0,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::default(),
        }, //REVIEW what do we do with this, given that we can't count casm steps
        inner_calls: vec![],
        storage_read_values: vec![],
        accessed_storage_keys: HashSet::new()
    })
}
