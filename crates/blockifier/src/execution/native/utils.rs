use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::hash::RandomState;
use std::rc::Rc;

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{BigInt, PrimeField};
use cairo_lang_sierra::ids::FunctionId;
use cairo_lang_sierra::program::Program as SierraProgram;
use cairo_lang_starknet_classes::contract_class::{ContractEntryPoint, ContractEntryPoints};
use cairo_native::cache::{AotProgramCache, JitProgramCache, ProgramCache};
use cairo_native::context::NativeContext;
use cairo_native::execution_result::ContractExecutionResult;
use cairo_native::executor::NativeExecutor;
use cairo_native::metadata::syscall_handler::SyscallHandlerMeta;
use cairo_native::starknet::{ResourceBounds, SyscallResult, TxV2Info, U256};
use cairo_native::OptLevel;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::ToBytes;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::Resource;
use starknet_types_core::felt::Felt;

use crate::execution::call_info::{
    CallExecution, CallInfo, OrderedEvent, OrderedL2ToL1Message, Retdata,
};
use crate::execution::entry_point::{CallEntryPoint, EntryPointExecutionResult};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::syscalls::hint_processor::{SyscallExecutionError, L1_GAS, L2_GAS};
use crate::execution::syscalls::secp::{SecpHintProcessor, SecpNewRequest, SecpNewResponse};
use crate::transaction::objects::CurrentTransactionInfo;

#[cfg(test)]
#[path = "utils_test.rs"]
pub mod test;

// An arbitrary number, chosen to avoid accidentally aligning with actually calculated gas
// To be deleted once cairo native gas handling can be used
pub const NATIVE_GAS_PLACEHOLDER: u64 = 12;

pub fn match_entrypoint(
    entry_point_type: EntryPointType,
    entrypoint_selector: EntryPointSelector,
    contract_entrypoints: &ContractEntryPoints,
) -> EntryPointExecutionResult<&ContractEntryPoint> {
    let entrypoints = match entry_point_type {
        EntryPointType::Constructor => &contract_entrypoints.constructor,
        EntryPointType::External => &contract_entrypoints.external,
        EntryPointType::L1Handler => &contract_entrypoints.l1_handler,
    };

    let cmp_selector_to_entrypoint =
        |selector: EntryPointSelector, entrypoint: &ContractEntryPoint| {
            let entrypoint_selector_str = entrypoint.selector.to_str_radix(16);
            let padded_selector_str = format!(
                "0x{}{}",
                "0".repeat(64 - entrypoint_selector_str.len()),
                entrypoint_selector_str
            );
            selector.0.to_string() == padded_selector_str
        };

    entrypoints
        .iter()
        .find(|entrypoint| cmp_selector_to_entrypoint(entrypoint_selector, entrypoint))
        .ok_or(EntryPointExecutionError::NativeExecutionError {
            info: format!("Entrypoint selector {} not found", entrypoint_selector.0),
        })
}

static NATIVE_CONTEXT: std::sync::OnceLock<cairo_native::context::NativeContext> =
    std::sync::OnceLock::new();

pub fn get_native_aot_program_cache<'context>() -> Rc<RefCell<ProgramCache<'context, ClassHash>>> {
    Rc::new(RefCell::new(ProgramCache::Aot(AotProgramCache::new(
        NATIVE_CONTEXT.get_or_init(NativeContext::new),
    ))))
}

pub fn get_native_jit_program_cache<'context>() -> Rc<RefCell<ProgramCache<'context, ClassHash>>> {
    Rc::new(RefCell::new(ProgramCache::Jit(JitProgramCache::new(
        NATIVE_CONTEXT.get_or_init(NativeContext::new),
    ))))
}

pub fn get_native_executor<'context>(
    class_hash: ClassHash,
    program: &SierraProgram,
    program_cache: Rc<RefCell<ProgramCache<'context, ClassHash>>>,
) -> NativeExecutor<'context> {
    let program_cache = &mut (*program_cache.borrow_mut());

    match program_cache {
        ProgramCache::Aot(cache) => {
            let cached_executor = cache.get(&class_hash);
            NativeExecutor::Aot(match cached_executor {
                Some(executor) => executor,
                None => cache.compile_and_insert(class_hash, program, OptLevel::Default),
            })
        }
        ProgramCache::Jit(cache) => {
            let cached_executor = cache.get(&class_hash);
            NativeExecutor::Jit(match cached_executor {
                Some(executor) => executor,
                None => cache.compile_and_insert(class_hash, program, OptLevel::Default),
            })
        }
    }
}

pub fn get_sierra_entry_function_id<'a>(
    matching_entrypoint: &'a ContractEntryPoint,
    sierra_program: &'a SierraProgram,
) -> &'a FunctionId {
    &sierra_program
        .funcs
        .iter()
        .find(|func| func.id.id == u64::try_from(matching_entrypoint.function_idx).unwrap())
        .unwrap()
        .id
}

pub fn stark_felt_to_native_felt(stark_felt: StarkFelt) -> Felt {
    Felt::from_bytes_be_slice(stark_felt.bytes())
}

pub fn native_felt_to_stark_felt(felt: Felt) -> StarkFelt {
    StarkFelt::new(felt.to_bytes_be()).unwrap()
}

pub fn contract_address_to_native_felt(contract_address: ContractAddress) -> Felt {
    Felt::from_bytes_be_slice(contract_address.0.key().bytes())
}

pub fn contract_entrypoint_to_entrypoint_selector(
    entrypoint: &ContractEntryPoint,
) -> EntryPointSelector {
    let selector_felt = Felt::from_bytes_be_slice(&entrypoint.selector.to_be_bytes());
    EntryPointSelector(native_felt_to_stark_felt(selector_felt))
}

pub fn run_native_executor(
    native_executor: NativeExecutor<'_>,
    sierra_entry_function_id: &FunctionId,
    call: &CallEntryPoint,
    syscall_handler: &SyscallHandlerMeta,
) -> EntryPointExecutionResult<ContractExecutionResult> {
    let stark_felts_to_native_felts = |data: &[StarkFelt]| -> Vec<Felt> {
        data.iter().map(|stark_felt| stark_felt_to_native_felt(*stark_felt)).collect_vec()
    };

    let execution_result = match native_executor {
        NativeExecutor::Aot(executor) => executor.invoke_contract_dynamic(
            sierra_entry_function_id,
            &stark_felts_to_native_felts(&call.calldata.0),
            Some(call.initial_gas.into()),
            Some(syscall_handler),
        ),
        NativeExecutor::Jit(executor) => executor.invoke_contract_dynamic(
            sierra_entry_function_id,
            &stark_felts_to_native_felts(&call.calldata.0),
            Some(call.initial_gas.into()),
            Some(syscall_handler),
        ),
    };

    match execution_result {
        Ok(res) if res.failure_flag => Err(EntryPointExecutionError::NativeExecutionError {
            info: if !res.return_values.is_empty() {
                decode_felts_as_str(&res.return_values)
            } else {
                String::from("Unknown error")
            },
        }),
        Err(runner_err) => {
            Err(EntryPointExecutionError::NativeUnexpectedError { source: runner_err })
        }
        Ok(res) => Ok(res),
    }
}

pub fn create_callinfo(
    call: CallEntryPoint,
    run_result: ContractExecutionResult,
    events: Vec<OrderedEvent>,
    l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    inner_calls: Vec<CallInfo>,
    storage_read_values: Vec<StarkFelt>,
    accessed_storage_keys: HashSet<StorageKey, RandomState>,
) -> Result<CallInfo, EntryPointExecutionError> {
    Ok(CallInfo {
        call,
        execution: CallExecution {
            retdata: Retdata(
                run_result.return_values.into_iter().map(native_felt_to_stark_felt).collect_vec(),
            ),
            events,
            l2_to_l1_messages,
            failed: run_result.failure_flag,
            gas_consumed: NATIVE_GAS_PLACEHOLDER,
        },
        resources: ExecutionResources {
            n_steps: 0,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::default(),
        },
        inner_calls,
        storage_read_values,
        accessed_storage_keys,
    })
}

pub fn u256_to_biguint(u256: U256) -> BigUint {
    let lo = BigUint::from(u256.lo);
    let hi = BigUint::from(u256.hi);

    hi + (lo << 128) // 128 is the size of lo
}

pub fn big4int_to_u256(b_int: BigInt<4>) -> U256 {
    let [a, b, c, d] = b_int.0;

    let lo = u128::from(a) | (u128::from(b) << 64);
    let hi = u128::from(c) | (u128::from(d) << 64);

    U256 { lo, hi }
}

pub fn encode_str_as_felts(msg: &str) -> Vec<Felt> {
    const CHUNK_SIZE: usize = 32;

    let data = msg.as_bytes().chunks(CHUNK_SIZE - 1);
    let mut encoding = vec![Felt::default(); data.len()];
    for (i, data_chunk) in data.enumerate() {
        let mut chunk = [0_u8; CHUNK_SIZE];
        chunk[1..data_chunk.len() + 1].copy_from_slice(data_chunk);
        encoding[i] = Felt::from_bytes_be(&chunk);
    }
    encoding
}

pub fn decode_felts_as_str(encoding: &[Felt]) -> String {
    let bytes_err: Vec<_> =
        encoding.iter().flat_map(|felt| felt.to_bytes_be()[1..32].to_vec()).collect();

    match String::from_utf8(bytes_err) {
        Ok(s) => s.trim_matches('\0').to_owned(),
        Err(_) => {
            let err_msgs = encoding
                .iter()
                .map(|felt| match String::from_utf8(felt.to_bytes_be()[1..32].to_vec()) {
                    Ok(s) => format!("{} ({})", s.trim_matches('\0'), felt),
                    Err(_) => felt.to_string(),
                })
                .join(", ");
            format!("[{}]", err_msgs)
        }
    }
}

pub fn allocate_point<Curve: SWCurveConfig>(
    point_x: U256,
    point_y: U256,
    hint_processor: &mut SecpHintProcessor<Curve>,
) -> SyscallResult<usize>
where
    Curve::BaseField: PrimeField,
{
    let request = SecpNewRequest { x: u256_to_biguint(point_x), y: u256_to_biguint(point_y) };

    let response = hint_processor.secp_new_unchecked(request);

    match response {
        // We can't receive None here, as the response is always Some from `secp_new_unchecked`.
        Ok(SecpNewResponse { optional_ec_point_id: id }) => Ok(id.unwrap()),
        Err(SyscallExecutionError::SyscallError { error_data }) => {
            Err(error_data.iter().map(|felt| stark_felt_to_native_felt(*felt)).collect())
        }
        Err(_) => unreachable!(
            "Can't receive an error other than SyscallError from `secp_new_unchecked`."
        ),
    }
}

pub fn default_tx_v2_info() -> TxV2Info {
    TxV2Info {
        version: Default::default(),
        account_contract_address: Default::default(),
        max_fee: 0,
        signature: vec![],
        transaction_hash: Default::default(),
        chain_id: Default::default(),
        nonce: Default::default(),
        resource_bounds: vec![],
        tip: 0,
        paymaster_data: vec![],
        nonce_data_availability_mode: 0,
        fee_data_availability_mode: 0,
        account_deployment_data: vec![],
    }
}

pub fn calculate_resource_bounds(
    tx_info: &CurrentTransactionInfo,
) -> SyscallResult<Vec<ResourceBounds>> {
    let l1_gas = StarkFelt::try_from(L1_GAS).map_err(|e| encode_str_as_felts(&e.to_string()))?;
    let l2_gas = StarkFelt::try_from(L2_GAS).map_err(|e| encode_str_as_felts(&e.to_string()))?;

    Ok(tx_info
        .resource_bounds
        .0
        .iter()
        .map(|(resource, resource_bound)| {
            let resource = match resource {
                Resource::L1Gas => l1_gas,
                Resource::L2Gas => l2_gas,
            };

            ResourceBounds {
                resource: stark_felt_to_native_felt(resource),
                max_amount: resource_bound.max_amount,
                max_price_per_unit: resource_bound.max_price_per_unit,
            }
        })
        .collect())
}
