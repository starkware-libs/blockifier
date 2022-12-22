use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{EntryPointType, StorageKey};
use starknet_api::transaction::CallData;

use crate::execution::contract_address::calculate_contract_address_from_hash;
use crate::execution::entry_point::{create_call_info_for_empty_constructor, CallEntryPoint};
use crate::execution::errors::SyscallExecutionError;
use crate::execution::execution_utils::{felt_to_bigint, get_felt_from_memory_cell};
use crate::execution::syscall_handling::{
    execute_inner_call, felt_to_bool, read_call_params, read_calldata, write_retdata,
    SyscallHandler,
};

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type ReadRequestResult = SyscallResult<SyscallRequest>;
pub type ExecutionResult = SyscallResult<SyscallResponse>;
pub type WriteResponseResult = SyscallResult<()>;

pub const CALL_CONTRACT_SELECTOR_BYTES: &[u8] = b"CallContract";
pub const DEPLOY_SELECTOR_BYTES: &[u8] = b"Deploy";
pub const LIBRARY_CALL_SELECTOR_BYTES: &[u8] = b"LibraryCall";
pub const STORAGE_READ_SELECTOR_BYTES: &[u8] = b"StorageRead";
pub const STORAGE_WRITE_SELECTOR_BYTES: &[u8] = b"StorageWrite";

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse {}

impl EmptyResponse {
    pub fn write(self, _vm: &mut VirtualMachine, _ptr: &Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

// TODO(AlonH, 21/12/2022): Couple all size constants with Cairo structs from the code.
pub const STORAGE_READ_REQUEST_SIZE: usize = 1;

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadRequest {
    pub address: StorageKey,
}

impl StorageReadRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        Ok(SyscallRequest::StorageRead(StorageReadRequest { address }))
    }

    pub fn execute(&self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        let value =
            syscall_handler.state.get_storage_at(syscall_handler.storage_address, self.address)?;
        Ok(SyscallResponse::StorageRead(StorageReadResponse { value: *value }))
    }
}

pub const STORAGE_READ_RESPONSE_SIZE: usize = 1;

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: StarkFelt,
}

impl StorageReadResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(self.value))?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address: StorageKey,
    pub value: StarkFelt,
}

pub const STORAGE_WRITE_REQUEST_SIZE: usize = 2;

impl StorageWriteRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let address: StarkFelt = get_felt_from_memory_cell(vm.get_maybe(ptr)?)?;
        let address: StorageKey = address.try_into()?;
        let value = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        Ok(SyscallRequest::StorageWrite(StorageWriteRequest { address, value }))
    }

    pub fn execute(&self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        syscall_handler.state.set_storage_at(
            syscall_handler.storage_address,
            self.address,
            self.value,
        );
        Ok(SyscallResponse::StorageWrite(EmptyResponse {}))
    }
}

pub const STORAGE_WRITE_RESPONSE_SIZE: usize = 0;

pub type StorageWriteResponse = EmptyResponse;

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractRequest {
    pub contract_address: ContractAddress,
    pub function_selector: EntryPointSelector,
    pub calldata: CallData,
}

pub const CALL_CONTRACT_REQUEST_SIZE: usize = 4;

impl CallContractRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let contract_address =
            ContractAddress(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?.try_into()?);
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

        Ok(SyscallRequest::CallContract(CallContractRequest {
            contract_address,
            function_selector,
            calldata,
        }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        let class_hash = *syscall_handler.state.get_class_hash_at(self.contract_address)?;
        let entry_point = CallEntryPoint {
            class_hash,
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.function_selector,
            calldata: self.calldata,
            storage_address: self.contract_address,
        };
        let retdata = execute_inner_call(entry_point, syscall_handler)?;

        Ok(SyscallResponse::CallContract(CallContractResponse { retdata }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CallContractResponse {
    pub retdata: Vec<StarkFelt>,
}

pub const CALL_CONTRACT_RESPONSE_SIZE: usize = 2;

impl CallContractResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        write_retdata(vm, ptr, self.retdata)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LibraryCallRequest {
    pub class_hash: ClassHash,
    pub function_selector: EntryPointSelector,
    pub calldata: CallData,
}

pub const LIBRARY_CALL_REQUEST_SIZE: usize = 4;

impl LibraryCallRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let class_hash = ClassHash(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
        let (function_selector, calldata) = read_call_params(vm, &(ptr + 1))?;

        Ok(SyscallRequest::LibraryCall(LibraryCallRequest {
            class_hash,
            function_selector,
            calldata,
        }))
    }

    pub fn execute(self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        let entry_point = CallEntryPoint {
            class_hash: self.class_hash,
            entry_point_type: EntryPointType::External,
            entry_point_selector: self.function_selector,
            calldata: self.calldata,
            storage_address: syscall_handler.storage_address,
        };
        let retdata = execute_inner_call(entry_point, syscall_handler)?;

        Ok(SyscallResponse::LibraryCall(LibraryCallResponse { retdata }))
    }
}

pub type LibraryCallResponse = CallContractResponse;

pub const LIBRARY_CALL_RESPONSE_SIZE: usize = CALL_CONTRACT_RESPONSE_SIZE;

#[derive(Debug, Eq, PartialEq)]
pub struct DeployRequest {
    pub class_hash: ClassHash,
    pub contract_address_salt: StarkFelt,
    pub constructor_calldata: CallData,
    pub deploy_from_zero: bool,
}

pub const DEPLOY_REQUEST_SIZE: usize = 5;

impl DeployRequest {
    pub fn read(vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let class_hash = ClassHash(get_felt_from_memory_cell(vm.get_maybe(ptr)?)?);
        let contract_address_salt = get_felt_from_memory_cell(vm.get_maybe(&(ptr + 1))?)?;
        let constructor_calldata = read_calldata(vm, &(ptr + 2))?;
        let deploy_from_zero = felt_to_bool(get_felt_from_memory_cell(vm.get_maybe(&(ptr + 4))?)?)?;

        Ok(SyscallRequest::Deploy(DeployRequest {
            class_hash,
            contract_address_salt,
            constructor_calldata,
            deploy_from_zero,
        }))
    }

    pub fn execute(&self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        let deployer_address = match self.deploy_from_zero {
            true => ContractAddress::default(),
            false => syscall_handler.storage_address,
        };
        let contract_address = calculate_contract_address_from_hash(
            self.contract_address_salt,
            self.class_hash,
            &self.constructor_calldata,
            &deployer_address,
        )?;

        syscall_handler.state.set_contract_hash(contract_address, self.class_hash)?;
        self.execute_constructor_entry_point(
            syscall_handler,
            contract_address,
            &self.constructor_calldata,
        )
    }

    pub fn execute_constructor_entry_point(
        &self,
        syscall_handler: &mut SyscallHandler,
        contract_address: ContractAddress,
        constructor_calldata: &CallData,
    ) -> ExecutionResult {
        let contract_class = syscall_handler.state.get_contract_class(&self.class_hash)?;
        let constructor_entry_points =
            &contract_class.entry_points_by_type[&EntryPointType::Constructor];

        let call_info = if constructor_entry_points.is_empty() {
            // Contract has no constructor.
            if !constructor_calldata.0.is_empty() {
                return Err(SyscallExecutionError::InvalidSyscallInput {
                    input: StarkFelt::from(constructor_calldata.0.len() as u64),
                    info: String::from("Cannot pass calldata to a contract with no constructor."),
                });
            }
            create_call_info_for_empty_constructor(self.class_hash, contract_address)
        } else {
            let constructor_entry_point = CallEntryPoint {
                class_hash: self.class_hash,
                entry_point_type: EntryPointType::Constructor,
                entry_point_selector: constructor_entry_points[0].selector,
                calldata: constructor_calldata.clone(),
                storage_address: contract_address,
            };
            constructor_entry_point.execute(&mut syscall_handler.state)?
        };

        syscall_handler.inner_calls.push(call_info);

        Ok(SyscallResponse::Deploy(DeployResponse { contract_address }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DeployResponse {
    pub contract_address: ContractAddress,
}

// DeployResponse struct in cairo contains three fields: contract_address, constructor_retdata_size
// and constructor_retdata. We return empty constructor_retdata.
pub const DEPLOY_RESPONSE_SIZE: usize = 3;

impl DeployResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        vm.insert_value(ptr, felt_to_bigint(*self.contract_address.0.key()))?;
        write_retdata(vm, &(ptr + 1), vec![])
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SyscallRequest {
    CallContract(CallContractRequest),
    Deploy(DeployRequest),
    LibraryCall(LibraryCallRequest),
    StorageRead(StorageReadRequest),
    StorageWrite(StorageWriteRequest),
}

impl SyscallRequest {
    pub fn read(selector: StarkFelt, vm: &VirtualMachine, ptr: &Relocatable) -> ReadRequestResult {
        let selector_bytes: &[u8] = selector.bytes();
        // Remove leading zero bytes from selector.
        let first_non_zero = selector_bytes.iter().position(|&byte| byte != b'\0').unwrap_or(32);
        match &selector_bytes[first_non_zero..32] {
            CALL_CONTRACT_SELECTOR_BYTES => CallContractRequest::read(vm, ptr),
            DEPLOY_SELECTOR_BYTES => DeployRequest::read(vm, ptr),
            LIBRARY_CALL_SELECTOR_BYTES => LibraryCallRequest::read(vm, ptr),
            STORAGE_READ_SELECTOR_BYTES => StorageReadRequest::read(vm, ptr),
            STORAGE_WRITE_SELECTOR_BYTES => StorageWriteRequest::read(vm, ptr),
            _ => Err(SyscallExecutionError::InvalidSyscallSelector(selector)),
        }
    }

    pub fn execute(self, syscall_handler: &mut SyscallHandler) -> ExecutionResult {
        match self {
            SyscallRequest::CallContract(request) => request.execute(syscall_handler),
            SyscallRequest::Deploy(request) => request.execute(syscall_handler),
            SyscallRequest::LibraryCall(request) => request.execute(syscall_handler),
            SyscallRequest::StorageRead(request) => request.execute(syscall_handler),
            SyscallRequest::StorageWrite(request) => request.execute(syscall_handler),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallRequest::CallContract(_) => CALL_CONTRACT_REQUEST_SIZE,
            SyscallRequest::Deploy(_) => DEPLOY_REQUEST_SIZE,
            SyscallRequest::LibraryCall(_) => LIBRARY_CALL_REQUEST_SIZE,
            SyscallRequest::StorageRead(_) => STORAGE_READ_REQUEST_SIZE,
            SyscallRequest::StorageWrite(_) => STORAGE_WRITE_REQUEST_SIZE,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SyscallResponse {
    CallContract(CallContractResponse),
    Deploy(DeployResponse),
    LibraryCall(LibraryCallResponse),
    StorageRead(StorageReadResponse),
    StorageWrite(EmptyResponse),
}

impl SyscallResponse {
    pub fn write(self, vm: &mut VirtualMachine, ptr: &Relocatable) -> WriteResponseResult {
        match self {
            SyscallResponse::CallContract(response) => response.write(vm, ptr),
            SyscallResponse::Deploy(response) => response.write(vm, ptr),
            SyscallResponse::LibraryCall(response) => response.write(vm, ptr),
            SyscallResponse::StorageRead(response) => response.write(vm, ptr),
            SyscallResponse::StorageWrite(response) => response.write(vm, ptr),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            SyscallResponse::CallContract(_) => CALL_CONTRACT_RESPONSE_SIZE,
            SyscallResponse::Deploy(_) => DEPLOY_RESPONSE_SIZE,
            SyscallResponse::LibraryCall(_) => LIBRARY_CALL_RESPONSE_SIZE,
            SyscallResponse::StorageRead(_) => STORAGE_READ_RESPONSE_SIZE,
            SyscallResponse::StorageWrite(_) => STORAGE_WRITE_RESPONSE_SIZE,
        }
    }
}
