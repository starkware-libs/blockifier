use std::collections::HashMap;

use cairo_felt::Felt252;
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
use num_bigint::BigUint;
use starknet_api::core::ClassHash;
use starknet_api::deprecated_contract_class::Program as DeprecatedProgram;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::Calldata;

use crate::execution::call_info::{CallInfo, Retdata};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    execute_constructor_entry_point, CallEntryPoint, ConstructorContext,
    EntryPointExecutionContext, EntryPointExecutionResult, ExecutionResources,
};
use crate::execution::errors::PostExecutionError;
use crate::execution::{deprecated_entry_point_execution, entry_point_execution};
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
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
) -> EntryPointExecutionResult<CallInfo> {
    match contract_class {
        ContractClass::V0(contract_class) => {
            deprecated_entry_point_execution::execute_entry_point_call(
                call,
                contract_class,
                state,
                resources,
                context,
            )
        }
        ContractClass::V1(contract_class) => entry_point_execution::execute_entry_point_call(
            call,
            contract_class,
            state,
            resources,
            context,
        ),
    }
}

pub fn read_execution_retdata(
    vm: &VirtualMachine,
    retdata_size: MaybeRelocatable,
    retdata_ptr: &MaybeRelocatable,
) -> Result<Retdata, PostExecutionError> {
    let retdata_size = match retdata_size {
        MaybeRelocatable::Int(retdata_size) => usize::try_from(retdata_size.to_bigint())
            .map_err(PostExecutionError::RetdataSizeTooBig)?,
        relocatable => {
            return Err(VirtualMachineError::ExpectedIntAtRange(Box::new(Some(relocatable))).into());
        }
    };

    Ok(Retdata(felt_range_from_ptr(vm, Relocatable::try_from(retdata_ptr)?, retdata_size)?))
}

pub fn stark_felt_from_ptr(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> Result<StarkFelt, VirtualMachineError> {
    Ok(felt_to_stark_felt(&felt_from_ptr(vm, ptr)?))
}

pub fn felt_from_ptr(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> Result<Felt252, VirtualMachineError> {
    let felt = vm.get_integer(*ptr)?.into_owned();
    *ptr = (*ptr + 1)?;
    Ok(felt)
}

pub fn write_u256(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    value: BigUint,
) -> Result<(), MemoryError> {
    write_felt(vm, ptr, Felt252::from(&value & BigUint::from(u128::MAX)))?;
    write_felt(vm, ptr, Felt252::from(value >> 128))
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
    let error_message_attributes = match program.attributes {
        serde_json::Value::Null => vec![],
        attributes => serde_json::from_value::<Vec<Attribute>>(attributes)?
            .into_iter()
            .filter(|attr| attr.name == "error_message")
            .collect(),
    };

    let instruction_locations = None;
    let reference_manager = serde_json::from_value::<ReferenceManager>(program.reference_manager)?;

    let program = Program::new(
        builtins,
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
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
    ctor_context: ConstructorContext,
    constructor_calldata: Calldata,
    remaining_gas: u64,
) -> EntryPointExecutionResult<CallInfo> {
    // Address allocation in the state is done before calling the constructor, so that it is
    // visible from it.
    let deployed_contract_address = ctor_context.storage_address;
    let current_class_hash = state.get_class_hash_at(deployed_contract_address)?;
    if current_class_hash != ClassHash::default() {
        return Err(StateError::UnavailableContractAddress(deployed_contract_address).into());
    }

    state.set_class_hash_at(deployed_contract_address, ctor_context.class_hash)?;

    let call_info = execute_constructor_entry_point(
        state,
        resources,
        context,
        ctor_context,
        constructor_calldata,
        remaining_gas,
    )?;

    Ok(call_info)
}

pub fn write_stark_felt(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    felt: StarkFelt,
) -> Result<(), MemoryError> {
    write_felt(vm, ptr, stark_felt_to_felt(felt))
}

pub fn write_felt(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    felt: Felt252,
) -> Result<(), MemoryError> {
    write_maybe_relocatable(vm, ptr, felt)
}

pub fn write_maybe_relocatable<T: Into<MaybeRelocatable>>(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    value: T,
) -> Result<(), MemoryError> {
    vm.insert_value(*ptr, value)?;
    *ptr = (*ptr + 1)?;
    Ok(())
}

pub fn format_panic_data(felts: &[StarkFelt]) -> String {
    let mut felts = felts.iter().map(|felt| stark_felt_to_felt(*felt));
    let mut items = Vec::new();
    while let Some(item) = format_next_item(&mut felts) {
        items.push(item.quote_if_string());
    }
    if let [item] = &items[..] { item.clone() } else { format!("({})", items.join(", ")) }
}

// TODO(yg): From here on this is a copied code from 2.4.0. Remove and instead call
// `format_next_item` from 2.4.0.
use cairo_felt::felt_str as felt252_str;
use itertools::Itertools;
use num_traits::{ToPrimitive, Zero};

pub const BYTE_ARRAY_MAGIC: &str =
    "46a6158a16a947e5916b2a2ca68501a45e93d7110e81aa2d6438b1c57c879a3";
pub const BYTES_IN_WORD: usize = 31;

/// A formatted string representation of anything formattable (e.g. ByteArray, felt, short-string).
pub struct FormattedItem {
    /// The formatted string representing the item.
    item: String,
    /// Whether the item is a string.
    is_string: bool,
}
impl FormattedItem {
    /// Returns the formatted item as is.
    pub fn get(self) -> String {
        self.item
    }
    /// Wraps the formatted item with quote, if it's a string. Otherwise returns it as is.
    pub fn quote_if_string(self) -> String {
        if self.is_string { format!("\"{}\"", self.item) } else { self.item }
    }
}

/// Formats a string or a short string / `felt252`. Returns the formatted string and a boolean
/// indicating whether it's a string. If can't format the item, returns None.
pub fn format_next_item<T>(values: &mut T) -> Option<FormattedItem>
where
    T: Iterator<Item = Felt252> + Clone,
{
    let Some(first_felt) = values.next() else {
        return None;
    };

    if first_felt == felt252_str!(BYTE_ARRAY_MAGIC, 16) {
        if let Some(string) = try_format_string(values) {
            return Some(FormattedItem { item: string, is_string: true });
        }
    }
    Some(FormattedItem { item: format_short_string(&first_felt), is_string: false })
}

/// Formats a `Felt252`, as a short string if possible.
fn format_short_string(value: &Felt252) -> String {
    let hex_value = value.to_biguint();
    match as_cairo_short_string(value) {
        Some(as_string) => format!("{hex_value:#x} ('{as_string}')"),
        None => format!("{hex_value:#x}"),
    }
}

/// Tries to format a string, represented as a sequence of `Felt252`s.
/// If the sequence is not a valid serialization of a ByteArray, returns None and doesn't change the
/// given iterator (`values`).
fn try_format_string<T>(values: &mut T) -> Option<String>
where
    T: Iterator<Item = Felt252> + Clone,
{
    // Clone the iterator and work with the clone. If the extraction of the string is successful,
    // change the original iterator to the one we worked with. If not, continue with the
    // original iterator at the original point.
    let mut cloned_values_iter = values.clone();

    let num_full_words = cloned_values_iter.next()?.to_usize()?;
    let full_words = cloned_values_iter.by_ref().take(num_full_words).collect_vec();
    let pending_word = cloned_values_iter.next()?;
    let pending_word_len = cloned_values_iter.next()?.to_usize()?;

    let full_words_string = full_words
        .into_iter()
        .map(|word| as_cairo_short_string_ex(&word, BYTES_IN_WORD))
        .collect::<Option<Vec<String>>>()?
        .join("");
    let pending_word_string = as_cairo_short_string_ex(&pending_word, pending_word_len)?;

    // Extraction was successful, change the original iterator to the one we worked with.
    *values = cloned_values_iter;

    Some(format!("{full_words_string}{pending_word_string}"))
}

/// Converts a bigint representing a felt252 to a Cairo short-string.
pub fn as_cairo_short_string(value: &Felt252) -> Option<String> {
    let mut as_string = String::default();
    let mut is_end = false;
    for byte in value.to_bytes_be() {
        if byte == 0 {
            is_end = true;
        } else if is_end {
            return None;
        } else if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            as_string.push(byte as char);
        } else {
            return None;
        }
    }
    Some(as_string)
}

/// Converts a bigint representing a felt252 to a Cairo short-string of the given length.
/// Nulls are allowed and length must be <= 31.
pub fn as_cairo_short_string_ex(value: &Felt252, length: usize) -> Option<String> {
    if length == 0 {
        return if value.is_zero() { Some("".to_string()) } else { None };
    }
    if length > 31 {
        // A short string can't be longer than 31 bytes.
        return None;
    }

    let bytes = value.to_bytes_be();
    let bytes_len = bytes.len();
    if bytes_len > length {
        // `value` has more bytes than expected.
        return None;
    }

    let mut as_string = "".to_string();
    for byte in bytes {
        if byte == 0 {
            as_string.push_str(r"\0");
        } else if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            as_string.push(byte as char);
        } else {
            as_string.push_str(format!(r"\x{:02x}", byte).as_str());
        }
    }

    // `to_bytes_be` misses starting nulls. Prepend them as needed.
    let missing_nulls = length - bytes_len;
    as_string.insert_str(0, &r"\0".repeat(missing_nulls));

    Some(as_string)
}
