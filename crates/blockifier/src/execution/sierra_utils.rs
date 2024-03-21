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
use cairo_native::starknet::U256;
use cairo_native::OptLevel;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::ToBytes;
use starknet_api::core::{ChainId, ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_types_core::felt::{Felt, FromStrError};

use super::call_info::{CallExecution, CallInfo, OrderedEvent, OrderedL2ToL1Message, Retdata};
use super::contract_class::SierraContractClassV1;
use super::entry_point::{CallEntryPoint, EntryPointExecutionResult};
use super::errors::EntryPointExecutionError;
use super::native_syscall_handler::NativeSyscallHandler;
use crate::execution::entry_point::EntryPointExecutionContext;
use crate::execution::syscalls::hint_processor::SyscallExecutionError;
use crate::execution::syscalls::secp::{SecpHintProcessor, SecpNewRequest, SecpNewResponse};
use crate::state::state_api::State;

// An arbitrary number, chosen to avoid accidentally aligning with actually calculated gas
// To be deleted once cairo native gas handling can be used
pub const NATIVE_GAS_PLACEHOLDER: u64 = 12;

pub fn get_program(contract_class: &SierraContractClassV1) -> &SierraProgram {
    &contract_class.sierra_program
}

pub fn get_entrypoints(contract_class: &SierraContractClassV1) -> &ContractEntryPoints {
    &contract_class.entry_points_by_type
}

pub fn match_entrypoint(
    entry_point_type: EntryPointType,
    entrypoint_selector: EntryPointSelector,
    contract_entrypoints: &ContractEntryPoints,
) -> &ContractEntryPoint {
    let entrypoints = match entry_point_type {
        EntryPointType::Constructor => &contract_entrypoints.constructor,
        EntryPointType::External => &contract_entrypoints.external,
        EntryPointType::L1Handler => &contract_entrypoints.l1_handler,
    };

    entrypoints
        .iter()
        .find(|entrypoint| cmp_selector_to_entrypoint(entrypoint_selector, entrypoint))
        .expect(&format!("entrypoint selector {0} not found", entrypoint_selector.0))
}

fn cmp_selector_to_entrypoint(
    selector: EntryPointSelector,
    contract_entrypoint: &ContractEntryPoint,
) -> bool {
    let entrypoint_selector_str = contract_entrypoint.selector.to_str_radix(16);
    let padded_selector_str =
        format!("0x{}{}", "0".repeat(64 - entrypoint_selector_str.len()), entrypoint_selector_str);
    selector.0.to_string() == padded_selector_str
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

pub fn get_code_class_hash(call: &CallEntryPoint, _state: &mut dyn State) -> ClassHash {
    // TODO investigate how this works for delegate calls, and whether this is already handled by
    // the blockifier (rendering this function inlinable)
    call.class_hash.unwrap()
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
        .find(|func| func.id.id == matching_entrypoint.function_idx as u64)
        .unwrap()
        .id
}

pub fn setup_syscall_handler<'state>(
    state: &'state mut dyn State,
    caller_address: ContractAddress,
    contract_address: ContractAddress,
    entry_point_selector: EntryPointSelector,
    execution_resources: &'state mut ExecutionResources,
    execution_context: &'state mut EntryPointExecutionContext,
    events: Vec<OrderedEvent>,
    l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    inner_calls: Vec<CallInfo>,
    secp256k1_hint_processor: SecpHintProcessor<ark_secp256k1::Config>,
    secp256r1_hint_processor: SecpHintProcessor<ark_secp256r1::Config>,
    storage_read_values: Vec<StarkFelt>,
    accessed_storage_keys: HashSet<StorageKey, RandomState>,
) -> NativeSyscallHandler<'state> {
    NativeSyscallHandler {
        state,
        caller_address,
        contract_address,
        entry_point_selector: entry_point_selector.0,
        execution_context,
        events,
        l2_to_l1_messages,
        execution_resources,
        inner_calls,
        secp256k1_hint_processor,
        secp256r1_hint_processor,
        storage_read_values,
        accessed_storage_keys,
    }
}

pub fn wrap_syscall_handler(syscall_handler: &mut NativeSyscallHandler<'_>) -> SyscallHandlerMeta {
    SyscallHandlerMeta::new(syscall_handler)
}

pub fn starkfelt_to_felt(starkfelt: StarkFelt) -> Felt {
    Felt::from_bytes_be_slice(starkfelt.bytes())
}

pub fn felt_to_starkfelt(felt: Felt) -> StarkFelt {
    StarkFelt::new(felt.to_bytes_be()).unwrap()
}

pub fn contract_address_to_felt(contract_address: ContractAddress) -> Felt {
    Felt::from_bytes_be_slice(contract_address.0.key().bytes())
}

pub fn contract_entrypoint_to_entrypoint_selector(
    entrypoint: &ContractEntryPoint,
) -> EntryPointSelector {
    let selector_felt = Felt::from_bytes_be_slice(&entrypoint.selector.to_be_bytes());
    EntryPointSelector(felt_to_starkfelt(selector_felt))
}

pub fn chain_id_to_felt(chain_id: &ChainId) -> Result<Felt, FromStrError> {
    Felt::from_hex(&chain_id.as_hex())
}

pub fn parse_starkfelt_string(felt: StarkFelt) -> String {
    String::from_utf8(felt.bytes().into()).unwrap()
}

fn starkfelts_to_felts(data: &[StarkFelt]) -> Vec<Felt> {
    data.iter().map(|starkfelt| starkfelt_to_felt(*starkfelt)).collect_vec()
}

pub fn run_native_executor(
    native_executor: NativeExecutor<'_>,
    sierra_entry_function_id: &FunctionId,
    call: &CallEntryPoint,
    syscall_handler: &SyscallHandlerMeta,
) -> EntryPointExecutionResult<ContractExecutionResult> {
    let execution_result = match native_executor {
        NativeExecutor::Aot(executor) => executor.invoke_contract_dynamic(
            sierra_entry_function_id,
            &starkfelts_to_felts(&call.calldata.0),
            Some(call.initial_gas as u128), // TODO track gas reduction?
            Some(syscall_handler),
        ),
        NativeExecutor::Jit(executor) => executor.invoke_contract_dynamic(
            sierra_entry_function_id,
            &starkfelts_to_felts(&call.calldata.0),
            Some(call.initial_gas as u128), // TODO track gas reduction?
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
) -> Result<CallInfo, super::errors::EntryPointExecutionError> {
    Ok(CallInfo {
        call,
        execution: CallExecution {
            retdata: Retdata(
                run_result.return_values.into_iter().map(felt_to_starkfelt).collect_vec(),
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

    let hi = (a as u128) | ((b as u128) << 64);
    let lo = (c as u128) | ((d as u128) << 64);

    U256 { lo, hi }
}

pub fn encode_str_as_felts(msg: &str) -> Vec<Felt> {
    const CHUNK_SIZE: usize = 32;

    let data = msg.as_bytes().chunks(CHUNK_SIZE - 1);
    let mut encoding = vec![Felt::default(); data.len()];
    for (i, data_chunk) in data.enumerate() {
        let mut chunk = [0_u8; CHUNK_SIZE];
        chunk[1..data_chunk.len() + 1].copy_from_slice(&data_chunk);
        encoding[i] = Felt::from_bytes_be(&chunk);
    }
    encoding
}

pub fn decode_felts_as_str(encoding: &[Felt]) -> String {
    let bytes_err: Vec<_> =
        encoding.iter().flat_map(|felt| felt.to_bytes_be()[1..32].to_vec()).collect();

    String::from_utf8(bytes_err).unwrap().trim_matches('\0').to_owned()
}

pub fn allocate_point<Curve: SWCurveConfig>(
    point_x: U256,
    point_y: U256,
    hint_processor: &mut SecpHintProcessor<Curve>,
) -> cairo_native::starknet::SyscallResult<usize>
where
    Curve::BaseField: PrimeField,
{
    let request = SecpNewRequest { x: u256_to_biguint(point_x), y: u256_to_biguint(point_y) };

    let response = hint_processor.secp_new_unchecked(request);

    match response {
        // We can't receive None here, as the response is always Some from `secp_new_unchecked`.
        Ok(SecpNewResponse { optional_ec_point_id: id }) => Ok(id.unwrap()),
        Err(SyscallExecutionError::SyscallError { error_data }) => {
            Err(error_data.iter().map(|felt| starkfelt_to_felt(*felt)).collect())
        }
        Err(_) => unreachable!(
            "Can't receive an error other than SyscallError from `secp_new_unchecked`."
        ),
    }
}

#[cfg(test)]
mod sierra_tests {
    use num_traits::Num;
    use starknet_api::core::PatriciaKey;
    use starknet_api::hash::StarkHash;
    use starknet_api::{contract_address, patricia_key};

    use super::*;

    #[test]
    fn test_chain_id_to_felt() {
        const CHAIN_ID: &str = "SN_GOERLI";

        let chain_id = ChainId(String::from(CHAIN_ID));
        let expected_felt = Felt::from_bytes_be_slice(CHAIN_ID.as_bytes());

        let actual_felt = chain_id_to_felt(&chain_id).unwrap();

        assert_eq!(actual_felt, expected_felt);
    }

    #[test]
    fn test_parse_starknet_string() {
        const EXPECTED_STRING: &str = "Hello StarkNet!";
        let expected_string_hex: String = {
            let mut hex = String::new();
            for byte in EXPECTED_STRING.as_bytes() {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        };

        let starkfelt_str = StarkFelt::try_from(expected_string_hex.as_str()).unwrap();
        let actual_string = parse_starkfelt_string(starkfelt_str);

        assert_eq!(actual_string.trim_matches('\0'), EXPECTED_STRING);
    }

    #[test]
    fn test_starkfelts_to_felts() {
        let starkfelts = vec![
            StarkFelt::try_from("0x01").unwrap(),
            StarkFelt::try_from("0x02").unwrap(),
            StarkFelt::try_from("0x03").unwrap(),
        ];
        let expected_felts = vec![Felt::from(1_u64), Felt::from(2_u64), Felt::from(3_u64)];

        let actual_felts = starkfelts_to_felts(&starkfelts);

        assert_eq!(actual_felts, expected_felts);
    }

    #[test]
    fn test_u256_to_biguint() {
        let u256 = U256 { lo: 0x1234_5678, hi: 0x9abc_def0 };

        let expected_biguint =
            BigUint::from_str_radix("123456780000000000000000000000009abcdef0", 16).unwrap();

        let actual_biguint = u256_to_biguint(u256);

        assert_eq!(actual_biguint, expected_biguint);
    }

    #[test]
    fn test_encode_decode_str() {
        const STR: &str = "Hello StarkNet!";

        let encoded_felt_array = encode_str_as_felts(STR);

        let decoded_felt_array = decode_felts_as_str(encoded_felt_array.as_slice());

        assert_eq!(STR, &decoded_felt_array);
    }

    #[test]
    fn test_felt_to_starkfelt() {
        const NUM: u128 = 123;

        let felt = Felt::from(NUM);
        let expected_starkfelt = StarkFelt::from_u128(NUM);
        let actual_starkfelt = felt_to_starkfelt(felt);

        assert_eq!(expected_starkfelt, actual_starkfelt);
    }

    #[test]
    fn test_starkfelt_to_felt() {
        const NUM: u128 = 123;

        let starkfelt = StarkFelt::from_u128(NUM);
        let expected_felt = Felt::from(NUM);
        let actual_felt = starkfelt_to_felt(starkfelt);

        assert_eq!(expected_felt, actual_felt);
    }

    #[test]
    fn test_contract_address_to_felt() {
        const NUM: u128 = 1234;

        let contract_address = contract_address!({ NUM });
        let expected_felt = Felt::from(NUM);
        let actual_felt = contract_address_to_felt(contract_address);

        assert_eq!(expected_felt, actual_felt);
    }

    #[test]
    fn test_contract_entrypoint_to_entrypoint_selector() {
        const NUM: u128 = 123;

        let entrypoint = ContractEntryPoint { selector: BigUint::from(NUM), function_idx: 0 };
        let expected_entrypoint_selector = EntryPointSelector(StarkFelt::from_u128(NUM));
        let actual_entrypoint_selector = contract_entrypoint_to_entrypoint_selector(&entrypoint);

        assert_eq!(expected_entrypoint_selector, actual_entrypoint_selector);
    }
}
