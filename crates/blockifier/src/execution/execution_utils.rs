use std::collections::HashMap;

use cairo_felt::Felt252;
use cairo_lang_runner::short_string::as_cairo_short_string;
use cairo_vm::serde::deserialize_program::{
    deserialize_array_of_bigint_hex, Attribute, HintParams, Identifier, ReferenceManager,
};
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::runners::cairo_runner::CairoArg;
use cairo_vm::vm::vm_core::VirtualMachine;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::Program as DeprecatedProgram;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    execute_constructor_entry_point, CallEntryPoint, CallInfo, EntryPointExecutionResult,
    ExecutionContext, Retdata,
};
use crate::execution::errors::PostExecutionError;
use crate::execution::{cairo1_execution, deprecated_execution};
use crate::state::errors::StateError;
use crate::state::state_api::State;

pub type Args = Vec<CairoArg>;

#[cfg(test)]
#[path = "execution_utils_test.rs"]
pub mod test;

pub fn stark_felt_to_felt(stark_felt: StarkFelt) -> Felt252 {
    Felt252::from_bytes_be(stark_felt.bytes())
}

pub fn felt_to_stark_felt(felt: &Felt252) -> StarkFelt {
    let biguint = format!("{:#x}", felt.to_biguint());
    StarkFelt::try_from(biguint.as_str()).expect("Felt252 must be in StarkFelt's range.")
}

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: ContractClass,
    state: &mut dyn State,
    context: &mut ExecutionContext,
) -> EntryPointExecutionResult<CallInfo> {
    match contract_class {
        ContractClass::V0(contract_class) => {
            deprecated_execution::execute_entry_point_call(call, contract_class, state, context)
        }
        ContractClass::V1(contract_class) => {
            cairo1_execution::execute_entry_point_call(call, contract_class, state, context)
        }
    }
}

pub fn read_execution_retdata(
    vm: VirtualMachine,
    retdata_size: MaybeRelocatable,
    retdata_ptr: MaybeRelocatable,
) -> Result<Retdata, PostExecutionError> {
    let retdata_size = match retdata_size {
        MaybeRelocatable::Int(retdata_size) => usize::try_from(retdata_size.to_bigint())
            .map_err(PostExecutionError::RetdataSizeTooBig)?,
        relocatable => {
            return Err(VirtualMachineError::ExpectedIntAtRange(Some(relocatable)).into());
        }
    };

    Ok(Retdata(felt_range_from_ptr(&vm, Relocatable::try_from(&retdata_ptr)?, retdata_size)?))
}

pub fn felt_from_ptr(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> Result<StarkFelt, VirtualMachineError> {
    let felt = felt_to_stark_felt(vm.get_integer(*ptr)?.as_ref());
    *ptr += 1;
    Ok(felt)
}

pub fn felt_range_from_ptr(
    vm: &VirtualMachine,
    ptr: Relocatable,
    size: usize,
) -> Result<Vec<StarkFelt>, VirtualMachineError> {
    let values = vm.get_integer_range(ptr, size)?;
    // Extract values as `StarkFelt`.
    let values = values.into_iter().map(|felt| felt_to_stark_felt(felt.as_ref())).collect();
    Ok(values)
}

// TODO(Elin,01/05/2023): aim to use LC's implementation once it's in a separate crate.
pub fn sn_api_to_cairo_vm_program(program: DeprecatedProgram) -> Result<Program, ProgramError> {
    let identifiers = serde_json::from_value::<HashMap<String, Identifier>>(program.identifiers)?;
    let builtins = serde_json::from_value(program.builtins)?;
    let data = deserialize_array_of_bigint_hex(program.data)?;
    let hints = serde_json::from_value::<HashMap<usize, Vec<HintParams>>>(program.hints)?;
    let main = None;
    let error_message_attributes = serde_json::from_value::<Vec<Attribute>>(program.attributes)?
        .into_iter()
        .filter(|attr| attr.name == "error_message")
        .collect();
    let instruction_locations = None;
    let reference_manager = serde_json::from_value::<ReferenceManager>(program.reference_manager)?;

    let program = Program::new(
        builtins,
        Felt252::prime().to_str_radix(16),
        data,
        main,
        hints,
        reference_manager,
        identifiers,
        error_message_attributes,
        instruction_locations,
    )?;

    Ok(program)
}

#[derive(Debug)]
// Invariant: read-only.
pub struct ReadOnlySegment {
    pub start_ptr: Relocatable,
    pub length: usize,
}

/// Represents read-only segments dynamically allocated during execution.
#[derive(Debug, Default)]
// Invariant: read-only.
pub struct ReadOnlySegments(Vec<ReadOnlySegment>);

impl ReadOnlySegments {
    pub fn allocate(
        &mut self,
        vm: &mut VirtualMachine,
        data: &Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, MemoryError> {
        let start_ptr = vm.add_memory_segment();
        self.0.push(ReadOnlySegment { start_ptr, length: data.len() });
        vm.load_data(start_ptr, data)?;
        Ok(start_ptr)
    }

    pub fn validate(&self, vm: &VirtualMachine) -> Result<(), PostExecutionError> {
        for segment in &self.0 {
            let used_size = vm
                .get_segment_used_size(segment.start_ptr.segment_index as usize)
                .expect("Segments must contain the allocated read-only segment.");
            if segment.length != used_size {
                return Err(PostExecutionError::SecurityValidationError(
                    "Read-only segments".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn mark_as_accessed(&self, vm: &mut VirtualMachine) -> Result<(), PostExecutionError> {
        for segment in &self.0 {
            vm.mark_address_range_as_accessed(segment.start_ptr, segment.length)?;
        }

        Ok(())
    }
}

/// Instantiates the given class and assigns it an address.
/// Returns the call info of the deployed class' constructor execution.
pub fn execute_deployment(
    state: &mut dyn State,
    context: &mut ExecutionContext,
    class_hash: ClassHash,
    deployed_contract_address: ContractAddress,
    deployer_address: ContractAddress,
    constructor_calldata: Calldata,
    is_deploy_account_tx: bool,
) -> EntryPointExecutionResult<CallInfo> {
    // Address allocation in the state is done before calling the constructor, so that it is
    // visible from it.
    let current_class_hash = state.get_class_hash_at(deployed_contract_address)?;
    if current_class_hash != ClassHash::default() {
        return Err(StateError::UnavailableContractAddress(deployed_contract_address).into());
    }

    state.set_class_hash_at(deployed_contract_address, class_hash)?;

    let code_address = if is_deploy_account_tx { None } else { Some(deployed_contract_address) };
    execute_constructor_entry_point(
        state,
        context,
        class_hash,
        code_address,
        deployed_contract_address,
        deployer_address,
        constructor_calldata,
    )
}

pub fn write_felt(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    felt: StarkFelt,
) -> Result<(), MemoryError> {
    write_maybe_relocatable(vm, ptr, stark_felt_to_felt(felt))
}

pub fn write_maybe_relocatable<T: Into<MaybeRelocatable>>(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    value: T,
) -> Result<(), MemoryError> {
    vm.insert_value(*ptr, value)?;
    *ptr += 1;
    Ok(())
}

pub fn felts_as_str(felts: &[StarkFelt]) -> String {
    felts
        .iter()
        .map(|felt| {
            as_cairo_short_string(&stark_felt_to_felt(*felt)).unwrap_or_else(|| felt.to_string())
        })
        .collect::<Vec<_>>()
        .join(", ")
}
