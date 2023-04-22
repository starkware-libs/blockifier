use std::collections::HashMap;
use std::convert::TryFrom;

use cairo_felt::Felt252;
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_vm::serde::deserialize_program::{
    ApTracking, FlowTrackingData, HintParams, ReferenceManager,
};
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer};
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointOffset, EntryPointType,
    Program as DeprecatedProgram,
};
use starknet_api::hash::StarkFelt;
use starknet_api::serde_utils::bytes_from_hex_str;

use crate::execution::execution_utils::sn_api_to_cairo_vm_program;

/// Represents a runnable StarkNet contract class (meaning, the program is runnable by the VM).
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClass {
    #[serde(deserialize_with = "deserialize_program")]
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl TryFrom<DeprecatedContractClass> for ContractClass {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        Ok(Self {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })
    }
}

fn casm_entrypoint_to_contract_class(entry_point: CasmContractEntryPoint) -> EntryPoint {
    EntryPoint {
        selector: EntryPointSelector(
            StarkFelt::new(
                bytes_from_hex_str::<32, false>(entry_point.selector.to_str_radix(16).as_str())
                    .unwrap(),
            )
            .unwrap(),
        ),
        offset: EntryPointOffset(entry_point.offset),
    }
}

pub fn casm_contract_into_contract_class(
    casm: CasmContractClass,
) -> Result<ContractClass, ProgramError> {
    let mut entry_points_by_type = HashMap::new();
    let mut external_entry_points = Vec::new();
    let mut l1_handler_entry_points = Vec::new();
    let mut constructor_entry_points = Vec::new();

    for entry_point in casm.entry_points_by_type.external {
        external_entry_points.push(casm_entrypoint_to_contract_class(entry_point));
    }

    for entry_point in casm.entry_points_by_type.l1_handler {
        l1_handler_entry_points.push(casm_entrypoint_to_contract_class(entry_point));
    }

    for entry_point in casm.entry_points_by_type.constructor {
        constructor_entry_points.push(casm_entrypoint_to_contract_class(entry_point));
    }

    entry_points_by_type.insert(EntryPointType::External, external_entry_points);
    entry_points_by_type.insert(EntryPointType::L1Handler, l1_handler_entry_points);
    entry_points_by_type.insert(EntryPointType::Constructor, constructor_entry_points);

    let hints = casm
        .pythonic_hints
        .unwrap()
        .iter()
        .map(|(hint_id, hint_codes)| {
            (
                *hint_id,
                hint_codes
                    .iter()
                    .map(|code| HintParams {
                        code: code.clone(),
                        accessible_scopes: vec![],
                        flow_tracking_data: FlowTrackingData {
                            ap_tracking: ApTracking { group: 0, offset: 0 },
                            reference_ids: HashMap::new(),
                        },
                    })
                    .collect(),
            )
        })
        .collect();

    let program = Program::new(
        Vec::new(),
        casm.bytecode
            .iter()
            .map(|big_uint_as_hex| {
                MaybeRelocatable::Int(Felt252::new(big_uint_as_hex.value.clone()))
            })
            .collect(),
        None,
        hints,
        // Fill missing fields with empty values.
        ReferenceManager { references: vec![] },
        HashMap::new(),
        Vec::new(),
        None,
    )?;

    Ok(ContractClass { program, entry_points_by_type })
}

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {
    let deprecated_program = DeprecatedProgram::deserialize(deserializer)?;
    sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
}
