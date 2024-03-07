use cairo_felt::Felt252;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_traits::ToPrimitive;
use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::{
    calculate_contract_address, ClassHash, ContractAddress, EntryPointSelector, EthAddress,
};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{
    Calldata, ContractAddressSalt, EventContent, EventData, EventKey, L2ToL1Payload,
};

use self::hint_processor::{
    create_retdata_segment, execute_inner_call, execute_library_call, felt_to_bool,
    read_call_params, read_calldata, read_felt_array, write_segment, EmitEventError,
    SyscallExecutionError, SyscallHintProcessor, BLOCK_NUMBER_OUT_OF_RANGE_ERROR,
};
use crate::abi::constants;
use crate::execution::call_info::{MessageToL1, OrderedEvent, OrderedL2ToL1Message};
use crate::execution::contract_class::ContractClass;
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::execution::entry_point::{CallEntryPoint, CallType, ConstructorContext};
use crate::execution::execution_utils::{
    execute_deployment, felt_from_ptr, felt_to_stark_felt, stark_felt_from_ptr, stark_felt_to_felt,
    write_felt, write_maybe_relocatable, write_stark_felt, ReadOnlySegment,
};
use crate::execution::syscalls::hint_processor::{INVALID_INPUT_LENGTH_ERROR, OUT_OF_GAS_ERROR};
use crate::transaction::transaction_utils::update_remaining_gas;
use crate::versioned_constants::{EventLimits, VersionedConstants};

pub mod hint_processor;
mod secp;

#[cfg(test)]
#[path = "syscall_tests.rs"]
pub mod syscall_tests;
#[cfg(test)]
#[path = "syscall_tests_vm.rs"]
mod syscall_tests_vm;

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type WriteResponseResult = SyscallResult<()>;

type SyscallSelector = DeprecatedSyscallSelector;

pub trait SyscallRequest: Sized {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<Self>;
}

pub trait SyscallResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult;
}

// Syscall header structs.
pub struct SyscallRequestWrapper<T: SyscallRequest> {
    pub gas_counter: u64,
    pub request: T,
}
impl<T: SyscallRequest> SyscallRequest for SyscallRequestWrapper<T> {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self> {
        let gas_counter = felt_from_ptr(vm, ptr)?;
        let gas_counter =
            gas_counter.to_u64().ok_or_else(|| SyscallExecutionError::InvalidSyscallInput {
                input: felt_to_stark_felt(&gas_counter),
                info: String::from("Unexpected gas."),
            })?;
        Ok(Self { gas_counter, request: T::read(vm, ptr)? })
    }
}

pub enum SyscallResponseWrapper<T: SyscallResponse> {
    Success { gas_counter: u64, response: T },
    Failure { gas_counter: u64, error_data: Vec<StarkFelt> },
}
impl<T: SyscallResponse> SyscallResponse for SyscallResponseWrapper<T> {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        match self {
            Self::Success { gas_counter, response } => {
                write_felt(vm, ptr, Felt252::from(gas_counter))?;
                // 0 to indicate success.
                write_stark_felt(vm, ptr, StarkFelt::from(0_u8))?;
                response.write(vm, ptr)
            }
            Self::Failure { gas_counter, error_data } => {
                write_felt(vm, ptr, Felt252::from(gas_counter))?;
                // 1 to indicate failure.
                write_stark_felt(vm, ptr, StarkFelt::from(1_u8))?;

                // Write the error data to a new memory segment.
                let revert_reason_start = vm.add_memory_segment();
                let revert_reason_end = vm.load_data(
                    revert_reason_start,
                    &error_data.into_iter().map(stark_felt_to_felt).map(Into::into).collect(),
                )?;

                // Write the start and end pointers of the error data.
                write_maybe_relocatable(vm, ptr, revert_reason_start)?;
                write_maybe_relocatable(vm, ptr, revert_reason_end)?;
                Ok(())
            }
        }
    }
}

// Common structs.

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyRequest;

impl SyscallRequest for EmptyRequest {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<EmptyRequest> {
        Ok(EmptyRequest)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse;

impl SyscallResponse for EmptyResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

#[derive(Debug)]
pub struct SingleSegmentResponse {
    segment: ReadOnlySegment,
}

impl SyscallResponse for SingleSegmentResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_segment(vm, ptr, self.segment)
    }
}

// CallContract syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractRequest {
    pub contract_address: ContractAddress,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl SyscallRequest for CallContractRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<CallContractRequest> {
        let contract_address = ContractAddress::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        let (function_selector, calldata) = read_call_params(vm, ptr)?;

        Ok(CallContractRequest { contract_address, function_selector, calldata })
    }
}

pub type CallContractResponse = SingleSegmentResponse;

pub fn call_contract(
    request: CallContractRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    remaining_gas: &mut u64,
) -> SyscallResult<CallContractResponse> {
    let storage_address = request.contract_address;
    if syscall_handler.is_validate_mode() && syscall_handler.storage_address() != storage_address {
        let error = SyscallExecutionError::InvalidSyscallInExecutionMode {
            syscall_name: "call_contract".to_string(),
            execution_mode: syscall_handler.execution_mode(),
        };
        return Err(error.as_call_contract_execution_error(storage_address));
    }
    let entry_point = CallEntryPoint {
        class_hash: None,
        code_address: Some(storage_address),
        entry_point_type: EntryPointType::External,
        entry_point_selector: request.function_selector,
        calldata: request.calldata,
        storage_address,
        caller_address: syscall_handler.storage_address(),
        call_type: CallType::Call,
        initial_gas: *remaining_gas,
    };
    let retdata_segment = execute_inner_call(entry_point, vm, syscall_handler, remaining_gas)
        .map_err(|error| error.as_call_contract_execution_error(storage_address))?;

    Ok(CallContractResponse { segment: retdata_segment })
}

// Deploy syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct DeployRequest {
    pub class_hash: ClassHash,
    pub contract_address_salt: ContractAddressSalt,
    pub constructor_calldata: Calldata,
    pub deploy_from_zero: bool,
}

impl SyscallRequest for DeployRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<DeployRequest> {
        let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);
        let contract_address_salt = ContractAddressSalt(stark_felt_from_ptr(vm, ptr)?);
        let constructor_calldata = read_calldata(vm, ptr)?;
        let deploy_from_zero = stark_felt_from_ptr(vm, ptr)?;

        Ok(DeployRequest {
            class_hash,
            contract_address_salt,
            constructor_calldata,
            deploy_from_zero: felt_to_bool(
                deploy_from_zero,
                "The deploy_from_zero field in the deploy system call must be 0 or 1.",
            )?,
        })
    }
}

#[derive(Debug)]
pub struct DeployResponse {
    pub contract_address: ContractAddress,
    pub constructor_retdata: ReadOnlySegment,
}

impl SyscallResponse for DeployResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_stark_felt(vm, ptr, *self.contract_address.0.key())?;
        write_segment(vm, ptr, self.constructor_retdata)
    }
}

pub fn deploy(
    request: DeployRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    remaining_gas: &mut u64,
) -> SyscallResult<DeployResponse> {
    let deployer_address = syscall_handler.storage_address();
    let deployer_address_for_calculation = match request.deploy_from_zero {
        true => ContractAddress::default(),
        false => deployer_address,
    };
    let deployed_contract_address = calculate_contract_address(
        request.contract_address_salt,
        request.class_hash,
        &request.constructor_calldata,
        deployer_address_for_calculation,
    )?;

    let ctor_context = ConstructorContext {
        class_hash: request.class_hash,
        code_address: Some(deployed_contract_address),
        storage_address: deployed_contract_address,
        caller_address: deployer_address,
    };
    let call_info = execute_deployment(
        syscall_handler.state,
        syscall_handler.resources,
        syscall_handler.context,
        ctor_context,
        request.constructor_calldata,
        *remaining_gas,
    )?;

    let constructor_retdata =
        create_retdata_segment(vm, syscall_handler, &call_info.execution.retdata.0)?;
    update_remaining_gas(remaining_gas, &call_info);

    syscall_handler.inner_calls.push(call_info);

    Ok(DeployResponse { contract_address: deployed_contract_address, constructor_retdata })
}

// EmitEvent syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct EmitEventRequest {
    pub content: EventContent,
}

impl SyscallRequest for EmitEventRequest {
    // The Cairo struct contains: `keys_len`, `keys`, `data_len`, `data`·
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmitEventRequest> {
        let keys =
            read_felt_array::<SyscallExecutionError>(vm, ptr)?.into_iter().map(EventKey).collect();
        let data = EventData(read_felt_array::<SyscallExecutionError>(vm, ptr)?);

        Ok(EmitEventRequest { content: EventContent { keys, data } })
    }
}

type EmitEventResponse = EmptyResponse;

pub fn exceeds_event_size_limit(
    versioned_constants: &VersionedConstants,
    n_emitted_events: usize,
    event: &EventContent,
) -> Result<(), EmitEventError> {
    let EventLimits { max_data_length, max_keys_length, max_n_emitted_events } =
        versioned_constants.tx_event_limits;
    if n_emitted_events > max_n_emitted_events {
        return Err(EmitEventError::ExceedsMaxNumberOfEmittedEvents {
            n_emitted_events,
            max_n_emitted_events,
        });
    }
    let keys_length = event.keys.len();
    if keys_length > max_keys_length {
        return Err(EmitEventError::ExceedsMaxKeysLength { keys_length, max_keys_length });
    }
    let data_length = event.data.0.len();
    if data_length > max_data_length {
        return Err(EmitEventError::ExceedsMaxDataLength { data_length, max_data_length });
    }

    Ok(())
}

pub fn emit_event(
    request: EmitEventRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<EmitEventResponse> {
    let execution_context = &mut syscall_handler.context;
    exceeds_event_size_limit(
        execution_context.versioned_constants(),
        execution_context.n_emitted_events + 1,
        &request.content,
    )?;
    let ordered_event =
        OrderedEvent { order: execution_context.n_emitted_events, event: request.content };
    syscall_handler.events.push(ordered_event);
    execution_context.n_emitted_events += 1;

    Ok(EmitEventResponse {})
}

// GetBlockHash syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockHashRequest {
    pub block_number: BlockNumber,
}

impl SyscallRequest for GetBlockHashRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<GetBlockHashRequest> {
        let felt = felt_from_ptr(vm, ptr)?;
        let block_number = BlockNumber(felt.to_u64().ok_or_else(|| {
            SyscallExecutionError::InvalidSyscallInput {
                input: felt_to_stark_felt(&felt),
                info: String::from("Block number must fit within 64 bits."),
            }
        })?);

        Ok(GetBlockHashRequest { block_number })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockHashResponse {
    pub block_hash: BlockHash,
}

impl SyscallResponse for GetBlockHashResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_stark_felt(vm, ptr, self.block_hash.0)?;
        Ok(())
    }
}

/// Returns the block hash of a given block_number.
/// Returns the expected block hash if the given block was created at least
/// [constants::STORED_BLOCK_HASH_BUFFER] blocks before the current block. Otherwise, returns an
/// error.
pub fn get_block_hash(
    request: GetBlockHashRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<GetBlockHashResponse> {
    if syscall_handler.is_validate_mode() {
        return Err(SyscallExecutionError::InvalidSyscallInExecutionMode {
            syscall_name: "get_block_hash".to_string(),
            execution_mode: syscall_handler.execution_mode(),
        });
    }

    let requested_block_number = request.block_number.0;
    let current_block_number =
        syscall_handler.context.tx_context.block_context.block_info.block_number.0;

    if current_block_number < constants::STORED_BLOCK_HASH_BUFFER
        || requested_block_number > current_block_number - constants::STORED_BLOCK_HASH_BUFFER
    {
        let out_of_range_error = StarkFelt::try_from(BLOCK_NUMBER_OUT_OF_RANGE_ERROR)
            .map_err(SyscallExecutionError::from)?;
        return Err(SyscallExecutionError::SyscallError { error_data: vec![out_of_range_error] });
    }

    let key = StorageKey::try_from(StarkFelt::from(requested_block_number))?;
    let block_hash_contract_address =
        ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))?;
    let block_hash =
        BlockHash(syscall_handler.state.get_storage_at(block_hash_contract_address, key)?);
    Ok(GetBlockHashResponse { block_hash })
}

// GetExecutionInfo syscall.

type GetExecutionInfoRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetExecutionInfoResponse {
    pub execution_info_ptr: Relocatable,
}

impl SyscallResponse for GetExecutionInfoResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, self.execution_info_ptr)?;
        Ok(())
    }
}
pub fn get_execution_info(
    _request: GetExecutionInfoRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<GetExecutionInfoResponse> {
    let execution_info_ptr = syscall_handler.get_or_allocate_execution_info_segment(vm)?;

    Ok(GetExecutionInfoResponse { execution_info_ptr })
}

// LibraryCall syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: Calldata,
}

impl SyscallRequest for LibraryCallRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<LibraryCallRequest> {
        let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);
        let (function_selector, calldata) = read_call_params(vm, ptr)?;

        Ok(LibraryCallRequest { class_hash, function_selector, calldata })
    }
}

type LibraryCallResponse = CallContractResponse;

pub fn library_call(
    request: LibraryCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    remaining_gas: &mut u64,
) -> SyscallResult<LibraryCallResponse> {
    let call_to_external = true;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        request.class_hash,
        call_to_external,
        request.function_selector,
        request.calldata,
        remaining_gas,
    )?;

    Ok(LibraryCallResponse { segment: retdata_segment })
}

// LibraryCallL1Handler syscall.

pub fn library_call_l1_handler(
    request: LibraryCallRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    remaining_gas: &mut u64,
) -> SyscallResult<LibraryCallResponse> {
    let call_to_external = false;
    let retdata_segment = execute_library_call(
        syscall_handler,
        vm,
        request.class_hash,
        call_to_external,
        request.function_selector,
        request.calldata,
        remaining_gas,
    )?;

    Ok(LibraryCallResponse { segment: retdata_segment })
}

// ReplaceClass syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct ReplaceClassRequest {
    pub class_hash: ClassHash,
}

impl SyscallRequest for ReplaceClassRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<ReplaceClassRequest> {
        let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);

        Ok(ReplaceClassRequest { class_hash })
    }
}

pub type ReplaceClassResponse = EmptyResponse;

pub fn replace_class(
    request: ReplaceClassRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<ReplaceClassResponse> {
    // Ensure the class is declared (by reading it), and of type V1.
    let class_hash = request.class_hash;
    let class = syscall_handler.state.get_compiled_contract_class(class_hash)?;

    match class {
        ContractClass::V0(_) => {
            Err(SyscallExecutionError::ForbiddenClassReplacement { class_hash })
        }
        ContractClass::V1(_) | ContractClass::V1Sierra(_) => {
            syscall_handler
                .state
                .set_class_hash_at(syscall_handler.storage_address(), class_hash)?;
            Ok(ReplaceClassResponse {})
        }
    }
}

// SendMessageToL1 syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct SendMessageToL1Request {
    pub message: MessageToL1,
}

impl SyscallRequest for SendMessageToL1Request {
    // The Cairo struct contains: `to_address`, `payload_size`, `payload`.
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SendMessageToL1Request> {
        let to_address = EthAddress::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        let payload = L2ToL1Payload(read_felt_array::<SyscallExecutionError>(vm, ptr)?);

        Ok(SendMessageToL1Request { message: MessageToL1 { to_address, payload } })
    }
}

type SendMessageToL1Response = EmptyResponse;

pub fn send_message_to_l1(
    request: SendMessageToL1Request,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<SendMessageToL1Response> {
    let execution_context = &mut syscall_handler.context;
    let ordered_message_to_l1 = OrderedL2ToL1Message {
        order: execution_context.n_sent_messages_to_l1,
        message: request.message,
    };
    syscall_handler.l2_to_l1_messages.push(ordered_message_to_l1);
    execution_context.n_sent_messages_to_l1 += 1;

    Ok(SendMessageToL1Response {})
}

// TODO(spapini): Do something with address domain in read and write.
// StorageRead syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadRequest {
    pub address_domain: StarkFelt,
    pub address: StorageKey,
}

impl SyscallRequest for StorageReadRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageReadRequest> {
        let address_domain = stark_felt_from_ptr(vm, ptr)?;
        if address_domain != StarkFelt::from(0_u8) {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        let address = StorageKey::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        Ok(StorageReadRequest { address_domain, address })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl SyscallResponse for StorageReadResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_stark_felt(vm, ptr, self.value)?;
        Ok(())
    }
}

pub fn storage_read(
    request: StorageReadRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<StorageReadResponse> {
    syscall_handler.get_contract_storage_at(request.address)
}

// StorageWrite syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address_domain: StarkFelt,
    pub address: StorageKey,
    pub value: StarkFelt,
}

impl SyscallRequest for StorageWriteRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageWriteRequest> {
        let address_domain = stark_felt_from_ptr(vm, ptr)?;
        if address_domain != StarkFelt::from(0_u8) {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        let address = StorageKey::try_from(stark_felt_from_ptr(vm, ptr)?)?;
        let value = stark_felt_from_ptr(vm, ptr)?;
        Ok(StorageWriteRequest { address_domain, address, value })
    }
}

pub type StorageWriteResponse = EmptyResponse;

pub fn storage_write(
    request: StorageWriteRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    _remaining_gas: &mut u64,
) -> SyscallResult<StorageWriteResponse> {
    syscall_handler.set_contract_storage_at(request.address, request.value)
}

// Keccak syscall.

#[derive(Debug, Eq, PartialEq)]
pub struct KeccakRequest {
    pub input_start: Relocatable,
    pub input_end: Relocatable,
}

impl SyscallRequest for KeccakRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<KeccakRequest> {
        let input_start = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        let input_end = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        Ok(KeccakRequest { input_start, input_end })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct KeccakResponse {
    pub result_low: Felt252,
    pub result_high: Felt252,
}

impl SyscallResponse for KeccakResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, self.result_low)?;
        write_felt(vm, ptr, self.result_high)?;
        Ok(())
    }
}

pub fn keccak(
    request: KeccakRequest,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    remaining_gas: &mut u64,
) -> SyscallResult<KeccakResponse> {
    let input_length = (request.input_end - request.input_start)?;

    const KECCAK_FULL_RATE_IN_WORDS: usize = 17;
    let (n_rounds, remainder) = num_integer::div_rem(input_length, KECCAK_FULL_RATE_IN_WORDS);

    if remainder != 0 {
        return Err(SyscallExecutionError::SyscallError {
            error_data: vec![StarkFelt::try_from(INVALID_INPUT_LENGTH_ERROR)
                .map_err(SyscallExecutionError::from)?],
        });
    }

    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let n_rounds_as_u64 = u64::try_from(n_rounds).expect("Failed to convert usize to u64.");
    let gas_cost =
        n_rounds_as_u64 * syscall_handler.context.get_gas_cost("keccak_round_cost_gas_cost");
    if gas_cost > *remaining_gas {
        let out_of_gas_error =
            StarkFelt::try_from(OUT_OF_GAS_ERROR).map_err(SyscallExecutionError::from)?;

        return Err(SyscallExecutionError::SyscallError { error_data: vec![out_of_gas_error] });
    }
    *remaining_gas -= gas_cost;

    // For the keccak system call we want to count the number of rounds rather than the number of
    // syscall invocations.
    syscall_handler.increment_syscall_count_by(&SyscallSelector::Keccak, n_rounds);

    let data = vm.get_integer_range(request.input_start, input_length)?;

    let mut state = [0u64; 25];
    for chunk in data.chunks(KECCAK_FULL_RATE_IN_WORDS) {
        for (i, val) in chunk.iter().enumerate() {
            state[i] ^= val.to_u64().ok_or_else(|| SyscallExecutionError::InvalidSyscallInput {
                input: felt_to_stark_felt(val),
                info: String::from("Invalid input for the keccak syscall."),
            })?;
        }
        keccak::f1600(&mut state)
    }

    Ok(KeccakResponse {
        result_low: (Felt252::from(state[1]) << 64u32) + Felt252::from(state[0]),
        result_high: (Felt252::from(state[3]) << 64u32) + Felt252::from(state[2]),
    })
}
