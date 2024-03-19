use std::any::Any;
use std::collections::{HashMap, HashSet};

use cairo_felt::Felt252;
use cairo_lang_casm::hints::{Hint, StarknetHint};
use cairo_lang_casm::operand::{BinOpOperand, DerefOrImmediate, Operation, Register, ResOperand};
use cairo_lang_runner::casm_run::execute_core_hint_base;
use cairo_vm::hint_processor::hint_processor_definition::{HintProcessorLogic, HintReference};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::runners::cairo_runner::{ExecutionResources, ResourceTracker, RunResources};
use cairo_vm::vm::vm_core::VirtualMachine;
use num_traits::Zero;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointType;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, Resource};
use starknet_api::StarknetApiError;
use thiserror::Error;

use crate::abi::sierra_types::SierraTypeError;
use crate::execution::call_info::{CallInfo, OrderedEvent, OrderedL2ToL1Message};
use crate::execution::common_hints::{ExecutionMode, HintExecutionResult};
use crate::execution::entry_point::{CallEntryPoint, CallType, EntryPointExecutionContext};
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::execution_utils::{
    felt_range_from_ptr, max_fee_for_execution_info, stark_felt_from_ptr, stark_felt_to_felt,
    write_maybe_relocatable, ReadOnlySegment, ReadOnlySegments,
};
use crate::execution::syscalls::secp::{
    secp256k1_add, secp256k1_get_point_from_x, secp256k1_get_xy, secp256k1_mul, secp256k1_new,
    secp256r1_add, secp256r1_get_point_from_x, secp256r1_get_xy, secp256r1_mul, secp256r1_new,
    SecpHintProcessor,
};
use crate::execution::syscalls::{
    call_contract, deploy, emit_event, get_block_hash, get_execution_info, keccak, library_call,
    library_call_l1_handler, replace_class, send_message_to_l1, storage_read, storage_write,
    StorageReadResponse, StorageWriteResponse, SyscallRequest, SyscallRequestWrapper,
    SyscallResponse, SyscallResponseWrapper, SyscallResult, SyscallSelector,
};
use crate::state::errors::StateError;
use crate::state::state_api::State;
use crate::transaction::objects::{CurrentTransactionInfo, TransactionInfo};
use crate::transaction::transaction_utils::update_remaining_gas;

pub type SyscallCounter = HashMap<SyscallSelector, usize>;

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Bad syscall_ptr; expected: {expected_ptr:?}, got: {actual_ptr:?}.")]
    BadSyscallPointer { expected_ptr: Relocatable, actual_ptr: Relocatable },
    #[error(transparent)]
    EmitEventError(#[from] EmitEventError),
    #[error("Cannot replace V1 class hash with V0 class hash: {class_hash}.")]
    ForbiddenClassReplacement { class_hash: ClassHash },
    #[error("Invalid address domain: {address_domain}.")]
    InvalidAddressDomain { address_domain: StarkFelt },
    #[error(transparent)]
    EntryPointExecutionError(#[from] EntryPointExecutionError),
    #[error("{error}")]
    CallContractExecutionError {
        storage_address: ContractAddress,
        error: Box<SyscallExecutionError>,
    },
    #[error("{error}")]
    LibraryCallExecutionError {
        class_hash: ClassHash,
        storage_address: ContractAddress,
        error: Box<SyscallExecutionError>,
    },
    #[error("Invalid syscall input: {input:?}; {info}")]
    InvalidSyscallInput { input: StarkFelt, info: String },
    #[error("Invalid syscall selector: {0:?}.")]
    InvalidSyscallSelector(StarkFelt),
    #[error("Unauthorized syscall {syscall_name} in execution mode {execution_mode}.")]
    InvalidSyscallInExecutionMode { syscall_name: String, execution_mode: ExecutionMode },
    #[error(transparent)]
    MathError(#[from] cairo_vm::types::errors::math_errors::MathError),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    SierraTypeError(#[from] SierraTypeError),
    #[error(transparent)]
    StarknetApiError(#[from] StarknetApiError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    VirtualMachineError(#[from] VirtualMachineError),
    #[error("Syscall error.")]
    SyscallError { error_data: Vec<StarkFelt> },
}

#[derive(Debug, Error)]
pub enum EmitEventError {
    #[error(
        "Exceeded the maximum keys length, keys length: {keys_length}, max keys length: \
         {max_keys_length}."
    )]
    ExceedsMaxKeysLength { keys_length: usize, max_keys_length: usize },
    #[error(
        "Exceeded the maximum data length, data length: {data_length}, max data length: \
         {max_data_length}."
    )]
    ExceedsMaxDataLength { data_length: usize, max_data_length: usize },
    #[error(
        "Exceeded the maximum number of events, number events: {n_emitted_events}, max number \
         events: {max_n_emitted_events}."
    )]
    ExceedsMaxNumberOfEmittedEvents { n_emitted_events: usize, max_n_emitted_events: usize },
}

// Needed for custom hint implementations (in our case, syscall hints) which must comply with the
// cairo-rs API.
impl From<SyscallExecutionError> for HintError {
    fn from(error: SyscallExecutionError) -> Self {
        HintError::Internal(VirtualMachineError::Other(error.into()))
    }
}

impl SyscallExecutionError {
    pub fn as_call_contract_execution_error(self, storage_address: ContractAddress) -> Self {
        SyscallExecutionError::CallContractExecutionError { storage_address, error: Box::new(self) }
    }

    pub fn as_lib_call_execution_error(
        self,
        class_hash: ClassHash,
        storage_address: ContractAddress,
    ) -> Self {
        SyscallExecutionError::LibraryCallExecutionError {
            class_hash,
            storage_address,
            error: Box::new(self),
        }
    }
}

/// Error codes returned by Cairo 1.0 code.

// "Out of gas";
pub const OUT_OF_GAS_ERROR: &str =
    "0x000000000000000000000000000000000000000000004f7574206f6620676173";
// "Block number out of range";
pub const BLOCK_NUMBER_OUT_OF_RANGE_ERROR: &str =
    "0x00000000000000426c6f636b206e756d626572206f7574206f662072616e6765";
// "Invalid execution mode";
pub const INVALID_EXECUTION_MODE_ERROR: &str = "0x00496e76616c696420657865637574696f6e206d6f6465";
// "Invalid input length";
pub const INVALID_INPUT_LENGTH_ERROR: &str =
    "0x000000000000000000000000496e76616c696420696e707574206c656e677468";
// "Invalid argument";
pub const INVALID_ARGUMENT: &str =
    "0x00000000000000000000000000000000496e76616c696420617267756d656e74";
// "L1_GAS";
pub const L1_GAS: &str = "0x00000000000000000000000000000000000000000000000000004c315f474153";
// "L2_GAS";
pub const L2_GAS: &str = "0x00000000000000000000000000000000000000000000000000004c325f474153";
// Failed to execute call
pub const FAILED_TO_EXECUTE_CALL: &str = "0x004661696c656420746f20657865637574652063616c6c";
// Failed to calculate address
pub const FAILED_TO_CALCULATE_CONTRACT_ADDRESS: &str =
    "0x004661696c656420746f2063616c63756c6174652061646472657373";

#[cfg(test)]
mod tests {
    use starknet_types_core::felt::Felt;

    use super::*;

    #[test]
    fn test_felt_from_hex() {
        assert!(Felt::from_hex(OUT_OF_GAS_ERROR).is_ok());
        assert!(Felt::from_hex(BLOCK_NUMBER_OUT_OF_RANGE_ERROR).is_ok());
        assert!(Felt::from_hex(INVALID_EXECUTION_MODE_ERROR).is_ok());
        assert!(Felt::from_hex(INVALID_INPUT_LENGTH_ERROR).is_ok());
        assert!(Felt::from_hex(INVALID_ARGUMENT).is_ok());
        assert!(Felt::from_hex(L1_GAS).is_ok());
        assert!(Felt::from_hex(L2_GAS).is_ok());
        assert!(Felt::from_hex(FAILED_TO_EXECUTE_CALL).is_ok());
        assert!(Felt::from_hex(FAILED_TO_CALCULATE_CONTRACT_ADDRESS).is_ok());
    }
}

/// Executes Starknet syscalls (stateful protocol hints) during the execution of an entry point
/// call.
pub struct SyscallHintProcessor<'a> {
    // Input for execution.
    pub state: &'a mut dyn State,
    pub resources: &'a mut ExecutionResources,
    pub context: &'a mut EntryPointExecutionContext,
    pub call: CallEntryPoint,

    // Execution results.
    /// Inner calls invoked by the current execution.
    pub inner_calls: Vec<CallInfo>,
    pub events: Vec<OrderedEvent>,
    pub l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub syscall_counter: SyscallCounter,

    // Fields needed for execution and validation.
    pub read_only_segments: ReadOnlySegments,
    pub syscall_ptr: Relocatable,

    // Additional information gathered during execution.
    pub read_values: Vec<StarkFelt>,
    pub accessed_keys: HashSet<StorageKey>,

    // Secp hint processors.
    pub secp256k1_hint_processor: SecpHintProcessor<ark_secp256k1::Config>,
    pub secp256r1_hint_processor: SecpHintProcessor<ark_secp256r1::Config>,

    // Additional fields.
    hints: &'a HashMap<String, Hint>,
    // Transaction info. and signature segments; allocated on-demand.
    execution_info_ptr: Option<Relocatable>,
}

impl<'a> SyscallHintProcessor<'a> {
    pub fn new(
        state: &'a mut dyn State,
        resources: &'a mut ExecutionResources,
        context: &'a mut EntryPointExecutionContext,
        initial_syscall_ptr: Relocatable,
        call: CallEntryPoint,
        hints: &'a HashMap<String, Hint>,
        read_only_segments: ReadOnlySegments,
    ) -> Self {
        SyscallHintProcessor {
            state,
            resources,
            context,
            call,
            inner_calls: vec![],
            events: vec![],
            l2_to_l1_messages: vec![],
            syscall_counter: SyscallCounter::default(),
            read_only_segments,
            syscall_ptr: initial_syscall_ptr,
            read_values: vec![],
            accessed_keys: HashSet::new(),
            hints,
            execution_info_ptr: None,
            secp256k1_hint_processor: SecpHintProcessor::default(),
            secp256r1_hint_processor: SecpHintProcessor::default(),
        }
    }

    pub fn storage_address(&self) -> ContractAddress {
        self.call.storage_address
    }

    pub fn caller_address(&self) -> ContractAddress {
        self.call.caller_address
    }

    pub fn entry_point_selector(&self) -> EntryPointSelector {
        self.call.entry_point_selector
    }

    pub fn execution_mode(&self) -> ExecutionMode {
        self.context.execution_mode
    }

    pub fn is_validate_mode(&self) -> bool {
        self.execution_mode() == ExecutionMode::Validate
    }

    pub fn verify_syscall_ptr(&self, actual_ptr: Relocatable) -> SyscallResult<()> {
        if actual_ptr != self.syscall_ptr {
            return Err(SyscallExecutionError::BadSyscallPointer {
                expected_ptr: self.syscall_ptr,
                actual_ptr,
            });
        }

        Ok(())
    }

    /// Infers and executes the next syscall.
    /// Must comply with the API of a hint function, as defined by the `HintProcessor`.
    pub fn execute_next_syscall(
        &mut self,
        vm: &mut VirtualMachine,
        hint: &StarknetHint,
    ) -> HintExecutionResult {
        let StarknetHint::SystemCall { system: syscall } = hint else {
            return Err(HintError::Internal(VirtualMachineError::Other(anyhow::anyhow!(
                "Test functions are unsupported on starknet."
            ))));
        };
        let initial_syscall_ptr = get_ptr_from_res_operand_unchecked(vm, syscall);
        self.verify_syscall_ptr(initial_syscall_ptr)?;

        let selector = SyscallSelector::try_from(self.read_next_syscall_selector(vm)?)?;

        // Keccak resource usage depends on the input length, so we increment the syscall count
        // in the syscall execution callback.
        if selector != SyscallSelector::Keccak {
            self.increment_syscall_count(&selector);
        }

        let get_gas_cost = |name: &str| -> u64 { self.context.get_gas_cost(name) };
        match selector {
            SyscallSelector::CallContract => {
                self.execute_syscall(vm, call_contract, get_gas_cost("call_contract_gas_cost"))
            }
            SyscallSelector::Deploy => {
                self.execute_syscall(vm, deploy, get_gas_cost("deploy_gas_cost"))
            }
            SyscallSelector::EmitEvent => {
                self.execute_syscall(vm, emit_event, get_gas_cost("emit_event_gas_cost"))
            }
            SyscallSelector::GetBlockHash => {
                self.execute_syscall(vm, get_block_hash, get_gas_cost("get_block_hash_gas_cost"))
            }
            SyscallSelector::GetExecutionInfo => self.execute_syscall(
                vm,
                get_execution_info,
                get_gas_cost("get_execution_info_gas_cost"),
            ),
            SyscallSelector::Keccak => {
                self.execute_syscall(vm, keccak, get_gas_cost("keccak_gas_cost"))
            }
            SyscallSelector::LibraryCall => {
                self.execute_syscall(vm, library_call, get_gas_cost("library_call_gas_cost"))
            }
            SyscallSelector::LibraryCallL1Handler => self.execute_syscall(
                vm,
                library_call_l1_handler,
                get_gas_cost("library_call_gas_cost"),
            ),
            SyscallSelector::ReplaceClass => {
                self.execute_syscall(vm, replace_class, get_gas_cost("replace_class_gas_cost"))
            }
            SyscallSelector::Secp256k1Add => {
                self.execute_syscall(vm, secp256k1_add, get_gas_cost("secp256k1_add_gas_cost"))
            }
            SyscallSelector::Secp256k1GetPointFromX => self.execute_syscall(
                vm,
                secp256k1_get_point_from_x,
                get_gas_cost("secp256k1_get_point_from_x_gas_cost"),
            ),
            SyscallSelector::Secp256k1GetXy => self.execute_syscall(
                vm,
                secp256k1_get_xy,
                get_gas_cost("secp256k1_get_xy_gas_cost"),
            ),
            SyscallSelector::Secp256k1Mul => {
                self.execute_syscall(vm, secp256k1_mul, get_gas_cost("secp256k1_mul_gas_cost"))
            }
            SyscallSelector::Secp256k1New => {
                self.execute_syscall(vm, secp256k1_new, get_gas_cost("secp256k1_new_gas_cost"))
            }
            SyscallSelector::Secp256r1Add => {
                self.execute_syscall(vm, secp256r1_add, get_gas_cost("secp256r1_add_gas_cost"))
            }
            SyscallSelector::Secp256r1GetPointFromX => self.execute_syscall(
                vm,
                secp256r1_get_point_from_x,
                get_gas_cost("secp256r1_get_point_from_x_gas_cost"),
            ),
            SyscallSelector::Secp256r1GetXy => self.execute_syscall(
                vm,
                secp256r1_get_xy,
                get_gas_cost("secp256r1_get_xy_gas_cost"),
            ),
            SyscallSelector::Secp256r1Mul => {
                self.execute_syscall(vm, secp256r1_mul, get_gas_cost("secp256r1_mul_gas_cost"))
            }
            SyscallSelector::Secp256r1New => {
                self.execute_syscall(vm, secp256r1_new, get_gas_cost("secp256r1_new_gas_cost"))
            }
            SyscallSelector::SendMessageToL1 => self.execute_syscall(
                vm,
                send_message_to_l1,
                get_gas_cost("send_message_to_l1_gas_cost"),
            ),
            SyscallSelector::StorageRead => {
                self.execute_syscall(vm, storage_read, get_gas_cost("storage_read_gas_cost"))
            }
            SyscallSelector::StorageWrite => {
                self.execute_syscall(vm, storage_write, get_gas_cost("storage_write_gas_cost"))
            }
            _ => Err(HintError::UnknownHint(
                format!("Unsupported syscall selector {selector:?}.").into(),
            )),
        }
    }

    pub fn get_or_allocate_execution_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        match self.execution_info_ptr {
            Some(execution_info_ptr) => Ok(execution_info_ptr),
            None => {
                let execution_info_ptr = self.allocate_execution_info_segment(vm)?;
                self.execution_info_ptr = Some(execution_info_ptr);
                Ok(execution_info_ptr)
            }
        }
    }

    fn allocate_tx_resource_bounds_segment(
        &mut self,
        vm: &mut VirtualMachine,
        tx_info: &CurrentTransactionInfo,
    ) -> SyscallResult<(Relocatable, Relocatable)> {
        let l1_gas = StarkFelt::try_from(L1_GAS).map_err(SyscallExecutionError::from)?;
        let l2_gas = StarkFelt::try_from(L2_GAS).map_err(SyscallExecutionError::from)?;
        let flat_resource_bounds: Vec<StarkFelt> = tx_info
            .resource_bounds
            .0
            .iter()
            .flat_map(|(resource, resource_bounds)| {
                let resource = match resource {
                    Resource::L1Gas => l1_gas,
                    Resource::L2Gas => l2_gas,
                };

                vec![
                    resource,
                    StarkFelt::from(resource_bounds.max_amount),
                    StarkFelt::from(resource_bounds.max_price_per_unit),
                ]
            })
            .collect();

        self.allocate_data_segment(vm, &flat_resource_bounds)
    }

    fn execute_syscall<Request, Response, ExecuteCallback>(
        &mut self,
        vm: &mut VirtualMachine,
        execute_callback: ExecuteCallback,
        syscall_gas_cost: u64,
    ) -> HintExecutionResult
    where
        Request: SyscallRequest + std::fmt::Debug,
        Response: SyscallResponse + std::fmt::Debug,
        ExecuteCallback: FnOnce(
            Request,
            &mut VirtualMachine,
            &mut SyscallHintProcessor<'_>,
            &mut u64, // Remaining gas.
        ) -> SyscallResult<Response>,
    {
        // Refund `SYSCALL_BASE_GAS_COST` as it was pre-charged.
        let required_gas = syscall_gas_cost - self.context.get_gas_cost("syscall_base_gas_cost");

        let SyscallRequestWrapper { gas_counter, request } =
            SyscallRequestWrapper::<Request>::read(vm, &mut self.syscall_ptr)?;

        if gas_counter < required_gas {
            //  Out of gas failure.
            let out_of_gas_error =
                StarkFelt::try_from(OUT_OF_GAS_ERROR).map_err(SyscallExecutionError::from)?;
            let response: SyscallResponseWrapper<Response> =
                SyscallResponseWrapper::Failure { gas_counter, error_data: vec![out_of_gas_error] };
            response.write(vm, &mut self.syscall_ptr)?;

            return Ok(());
        }

        // Execute.
        let mut remaining_gas = gas_counter - required_gas;
        let original_response = execute_callback(request, vm, self, &mut remaining_gas);
        let response = match original_response {
            Ok(response) => {
                SyscallResponseWrapper::Success { gas_counter: remaining_gas, response }
            }
            Err(SyscallExecutionError::SyscallError { error_data: data }) => {
                SyscallResponseWrapper::Failure { gas_counter: remaining_gas, error_data: data }
            }
            Err(error) => return Err(error.into()),
        };

        response.write(vm, &mut self.syscall_ptr)?;

        Ok(())
    }

    fn read_next_syscall_selector(&mut self, vm: &mut VirtualMachine) -> SyscallResult<StarkFelt> {
        let selector = stark_felt_from_ptr(vm, &mut self.syscall_ptr)?;

        Ok(selector)
    }

    pub fn increment_syscall_count_by(&mut self, selector: &SyscallSelector, n: usize) {
        let syscall_count = self.syscall_counter.entry(*selector).or_default();
        *syscall_count += n;
    }

    fn increment_syscall_count(&mut self, selector: &SyscallSelector) {
        self.increment_syscall_count_by(selector, 1);
    }

    fn allocate_execution_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        let block_info_ptr = self.allocate_block_info_segment(vm)?;
        let tx_info_ptr = self.allocate_tx_info_segment(vm)?;

        let additional_info: Vec<MaybeRelocatable> = vec![
            block_info_ptr.into(),
            tx_info_ptr.into(),
            stark_felt_to_felt(*self.caller_address().0.key()).into(),
            stark_felt_to_felt(*self.storage_address().0.key()).into(),
            stark_felt_to_felt(self.entry_point_selector().0).into(),
        ];
        let execution_info_segment_start_ptr =
            self.read_only_segments.allocate(vm, &additional_info)?;

        Ok(execution_info_segment_start_ptr)
    }

    fn allocate_block_info_segment(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> SyscallResult<Relocatable> {
        let block_info = &self.context.tx_context.block_context.block_info;
        let block_timestamp = block_info.block_timestamp.0;
        let block_number = block_info.block_number.0;
        let versioned_constants = self.context.versioned_constants();
        let block_data: Vec<StarkFelt> = if self.is_validate_mode() {
            // Round down to the nearest multiple of validate_block_number_rounding.
            let validate_block_number_rounding =
                versioned_constants.get_validate_block_number_rounding();
            let rounded_block_number =
                (block_number / validate_block_number_rounding) * validate_block_number_rounding;
            // Round down to the nearest multiple of validate_timestamp_rounding.
            let validate_timestamp_rounding = versioned_constants.get_validate_timestamp_rounding();
            let rounded_timestamp =
                (block_timestamp / validate_timestamp_rounding) * validate_timestamp_rounding;

            vec![
                StarkFelt::from(rounded_block_number),
                StarkFelt::from(rounded_timestamp),
                StarkFelt::ZERO,
            ]
        } else {
            vec![
                StarkFelt::from(block_number),
                StarkFelt::from(block_timestamp),
                *block_info.sequencer_address.0.key(),
            ]
        };
        let (block_info_segment_start_ptr, _) = self.allocate_data_segment(vm, &block_data)?;

        Ok(block_info_segment_start_ptr)
    }

    fn allocate_data_segment(
        &mut self,
        vm: &mut VirtualMachine,
        data: &[StarkFelt],
    ) -> SyscallResult<(Relocatable, Relocatable)> {
        let data = data.iter().map(|&x| MaybeRelocatable::from(stark_felt_to_felt(x))).collect();
        let data_segment_start_ptr = self.read_only_segments.allocate(vm, &data)?;
        let data_segment_end_ptr = (data_segment_start_ptr + data.len())?;
        Ok((data_segment_start_ptr, data_segment_end_ptr))
    }

    fn allocate_tx_info_segment(&mut self, vm: &mut VirtualMachine) -> SyscallResult<Relocatable> {
        let tx_info = &self.context.tx_context.clone().tx_info;
        let (tx_signature_start_ptr, tx_signature_end_ptr) =
            &self.allocate_data_segment(vm, &tx_info.signature().0)?;

        let mut tx_data: Vec<MaybeRelocatable> = vec![
            stark_felt_to_felt(tx_info.signed_version().0).into(),
            stark_felt_to_felt(*tx_info.sender_address().0.key()).into(),
            max_fee_for_execution_info(tx_info).into(),
            tx_signature_start_ptr.into(),
            tx_signature_end_ptr.into(),
            stark_felt_to_felt((tx_info).transaction_hash().0).into(),
            Felt252::from_bytes_be(
                self.context.tx_context.block_context.chain_info.chain_id.0.as_bytes(),
            )
            .into(),
            stark_felt_to_felt((tx_info).nonce().0).into(),
        ];

        match tx_info {
            TransactionInfo::Current(context) => {
                let (tx_resource_bounds_start_ptr, tx_resource_bounds_end_ptr) =
                    &self.allocate_tx_resource_bounds_segment(vm, context)?;

                let (tx_paymaster_data_start_ptr, tx_paymaster_data_end_ptr) =
                    &self.allocate_data_segment(vm, &context.paymaster_data.0)?;

                let (tx_account_deployment_data_start_ptr, tx_account_deployment_data_end_ptr) =
                    &self.allocate_data_segment(vm, &context.account_deployment_data.0)?;

                tx_data.extend_from_slice(&[
                    tx_resource_bounds_start_ptr.into(),
                    tx_resource_bounds_end_ptr.into(),
                    Felt252::from(context.tip.0).into(),
                    tx_paymaster_data_start_ptr.into(),
                    tx_paymaster_data_end_ptr.into(),
                    stark_felt_to_felt(context.nonce_data_availability_mode.into()).into(),
                    stark_felt_to_felt(context.fee_data_availability_mode.into()).into(),
                    tx_account_deployment_data_start_ptr.into(),
                    tx_account_deployment_data_end_ptr.into(),
                ]);
            }
            TransactionInfo::Deprecated(_) => {
                let zero_felt: MaybeRelocatable = Felt252::zero().into();
                tx_data.extend_from_slice(&[
                    zero_felt.clone(), // Empty segment of resource bounds (start ptr).
                    zero_felt.clone(), // Empty segment of resource bounds (end ptr).
                    zero_felt.clone(), // Tip.
                    zero_felt.clone(), // Empty segment of paymaster data (start ptr).
                    zero_felt.clone(), // Empty segment of paymaster data (end ptr).
                    zero_felt.clone(), // Nonce DA mode.
                    zero_felt.clone(), // Fee DA mode.
                    zero_felt.clone(), // Empty segment of account deployment data (start ptr).
                    zero_felt,         // Empty segment of account deployment data (end ptr).
                ]);
            }
        };

        let tx_info_start_ptr = self.read_only_segments.allocate(vm, &tx_data)?;
        Ok(tx_info_start_ptr)
    }

    pub fn get_contract_storage_at(
        &mut self,
        key: StorageKey,
    ) -> SyscallResult<StorageReadResponse> {
        self.accessed_keys.insert(key);
        let value = self.state.get_storage_at(self.storage_address(), key)?;
        self.read_values.push(value);

        Ok(StorageReadResponse { value })
    }

    pub fn set_contract_storage_at(
        &mut self,
        key: StorageKey,
        value: StarkFelt,
    ) -> SyscallResult<StorageWriteResponse> {
        self.accessed_keys.insert(key);
        self.state.set_storage_at(self.storage_address(), key, value)?;

        Ok(StorageWriteResponse {})
    }
}

/// Retrieves a [Relocatable] from the VM given a [ResOperand].
/// A [ResOperand] represents a CASM result expression, and is deserialized with the hint.
fn get_ptr_from_res_operand_unchecked(vm: &mut VirtualMachine, res: &ResOperand) -> Relocatable {
    let (cell, base_offset) = match res {
        ResOperand::Deref(cell) => (cell, Felt252::from(0)),
        ResOperand::BinOp(BinOpOperand {
            op: Operation::Add,
            a,
            b: DerefOrImmediate::Immediate(b),
        }) => (a, Felt252::from(b.clone().value)),
        _ => panic!("Illegal argument for a buffer."),
    };
    let base = match cell.register {
        Register::AP => vm.get_ap(),
        Register::FP => vm.get_fp(),
    };
    let cell_reloc = (base + (i32::from(cell.offset))).unwrap();
    (vm.get_relocatable(cell_reloc).unwrap() + &base_offset).unwrap()
}

impl ResourceTracker for SyscallHintProcessor<'_> {
    fn consumed(&self) -> bool {
        self.context.vm_run_resources.consumed()
    }

    fn consume_step(&mut self) {
        self.context.vm_run_resources.consume_step()
    }

    fn get_n_steps(&self) -> Option<usize> {
        self.context.vm_run_resources.get_n_steps()
    }

    fn run_resources(&self) -> &RunResources {
        self.context.vm_run_resources.run_resources()
    }
}

impl HintProcessorLogic for SyscallHintProcessor<'_> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        _constants: &HashMap<String, Felt252>,
    ) -> HintExecutionResult {
        let hint = hint_data.downcast_ref::<Hint>().ok_or(HintError::WrongHintData)?;
        match hint {
            Hint::Core(hint) => execute_core_hint_base(vm, exec_scopes, hint),
            Hint::Starknet(hint) => self.execute_next_syscall(vm, hint),
        }
    }

    /// Trait function to store hint in the hint processor by string.
    fn compile_hint(
        &self,
        hint_code: &str,
        _ap_tracking_data: &ApTracking,
        _reference_ids: &HashMap<String, usize>,
        _references: &[HintReference],
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        Ok(Box::new(self.hints[hint_code].clone()))
    }
}

pub fn felt_to_bool(felt: StarkFelt, error_info: &str) -> SyscallResult<bool> {
    if felt == StarkFelt::from(0_u8) {
        Ok(false)
    } else if felt == StarkFelt::from(1_u8) {
        Ok(true)
    } else {
        Err(SyscallExecutionError::InvalidSyscallInput { input: felt, info: error_info.into() })
    }
}

pub fn read_calldata(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Calldata> {
    Ok(Calldata(read_felt_array::<SyscallExecutionError>(vm, ptr)?.into()))
}

pub fn read_call_params(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> SyscallResult<(EntryPointSelector, Calldata)> {
    let function_selector = EntryPointSelector(stark_felt_from_ptr(vm, ptr)?);
    let calldata = read_calldata(vm, ptr)?;

    Ok((function_selector, calldata))
}

pub fn execute_inner_call(
    call: CallEntryPoint,
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    remaining_gas: &mut u64,
) -> SyscallResult<ReadOnlySegment> {
    let call_info =
        call.execute(syscall_handler.state, syscall_handler.resources, syscall_handler.context)?;
    let raw_retdata = &call_info.execution.retdata.0;

    if call_info.execution.failed {
        // TODO(spapini): Append an error word according to starknet spec if needed.
        // Something like "EXECUTION_ERROR".
        return Err(SyscallExecutionError::SyscallError { error_data: raw_retdata.clone() });
    }

    let retdata_segment = create_retdata_segment(vm, syscall_handler, raw_retdata)?;
    update_remaining_gas(remaining_gas, &call_info);

    syscall_handler.inner_calls.push(call_info);

    Ok(retdata_segment)
}

pub fn create_retdata_segment(
    vm: &mut VirtualMachine,
    syscall_handler: &mut SyscallHintProcessor<'_>,
    raw_retdata: &[StarkFelt],
) -> SyscallResult<ReadOnlySegment> {
    let (retdata_segment_start_ptr, _) = syscall_handler.allocate_data_segment(vm, raw_retdata)?;

    Ok(ReadOnlySegment { start_ptr: retdata_segment_start_ptr, length: raw_retdata.len() })
}

pub fn execute_library_call(
    syscall_handler: &mut SyscallHintProcessor<'_>,
    vm: &mut VirtualMachine,
    class_hash: ClassHash,
    call_to_external: bool,
    entry_point_selector: EntryPointSelector,
    calldata: Calldata,
    remaining_gas: &mut u64,
) -> SyscallResult<ReadOnlySegment> {
    let entry_point_type =
        if call_to_external { EntryPointType::External } else { EntryPointType::L1Handler };
    let entry_point = CallEntryPoint {
        class_hash: Some(class_hash),
        code_address: None,
        entry_point_type,
        entry_point_selector,
        calldata,
        // The call context remains the same in a library call.
        storage_address: syscall_handler.storage_address(),
        caller_address: syscall_handler.caller_address(),
        call_type: CallType::Delegate,
        initial_gas: *remaining_gas,
    };

    execute_inner_call(entry_point, vm, syscall_handler, remaining_gas).map_err(|error| {
        error.as_lib_call_execution_error(class_hash, syscall_handler.storage_address())
    })
}

pub fn read_felt_array<TErr>(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> Result<Vec<StarkFelt>, TErr>
where
    TErr: From<StarknetApiError> + From<VirtualMachineError> + From<MemoryError> + From<MathError>,
{
    let array_data_start_ptr = vm.get_relocatable(*ptr)?;
    *ptr = (*ptr + 1)?;
    let array_data_end_ptr = vm.get_relocatable(*ptr)?;
    *ptr = (*ptr + 1)?;
    let array_size = (array_data_end_ptr - array_data_start_ptr)?;

    Ok(felt_range_from_ptr(vm, array_data_start_ptr, array_size)?)
}

pub fn write_segment(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    segment: ReadOnlySegment,
) -> SyscallResult<()> {
    write_maybe_relocatable(vm, ptr, segment.start_ptr)?;
    let segment_end_ptr = (segment.start_ptr + segment.length)?;
    write_maybe_relocatable(vm, ptr, segment_end_ptr)?;

    Ok(())
}
