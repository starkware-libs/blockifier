use std::collections::HashMap;
use std::sync::Arc;

use cairo_lang_casm;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::felt::Felt252;
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

use super::execution_utils::felt_to_stark_felt;
use crate::execution::execution_utils::sn_api_to_cairo_vm_program;

/// Represents a runnable StarkNet contract class (meaning, the program is runnable by the VM).
/// We wrap the actual class in an Arc to avoid cloning the program when cloning the class.
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClass(pub Arc<ContractClassInner>);

impl TryFrom<DeprecatedContractClass> for ContractClass {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(ContractClassInner {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })))
    }
}

// TODO(spapini): Share with cairo-lang-runner.
fn hint_to_hint_params(hint: &cairo_lang_casm::hints::Hint) -> HintParams {
    HintParams {
        code: hint.to_string(),
        accessible_scopes: vec![],
        flow_tracking_data: FlowTrackingData {
            ap_tracking: ApTracking::new(),
            reference_ids: HashMap::new(),
        },
    }
}

impl TryFrom<CasmContractClass> for ContractClass {
    type Error = ProgramError;

    fn try_from(class: CasmContractClass) -> Result<Self, Self::Error> {
        let data: Vec<MaybeRelocatable> = class
            .bytecode
            .into_iter()
            .map(|x| MaybeRelocatable::from(Felt252::from(x.value)))
            .collect();
        let hints = class
            .hints
            .into_iter()
            .map(|(i, hints)| (i, hints.iter().map(hint_to_hint_params).collect()))
            .collect();

        let program = Program::new(
            vec![], // The builtins will be set on each call.
            data,
            Some(0),
            hints,
            ReferenceManager { references: Vec::new() },
            HashMap::new(),
            vec![],
            None,
        )?;

        let mut entry_points_by_type = HashMap::new();
        // TODO(spapini): Add builtins to the entry points.
        entry_points_by_type.insert(
            EntryPointType::External,
            class
                .entry_points_by_type
                .external
                .into_iter()
                .map(|ep| EntryPoint {
                    selector: EntryPointSelector(felt_to_stark_felt(
                        &Felt252::try_from(ep.selector).unwrap(),
                    )),
                    offset: EntryPointOffset(ep.offset),
                })
                .collect(),
        );
        entry_points_by_type.insert(
            EntryPointType::L1Handler,
            class
                .entry_points_by_type
                .l1_handler
                .into_iter()
                .map(|ep| EntryPoint {
                    selector: EntryPointSelector(felt_to_stark_felt(
                        &Felt252::try_from(ep.selector).unwrap(),
                    )),
                    offset: EntryPointOffset(ep.offset),
                })
                .collect(),
        );
        entry_points_by_type.insert(
            EntryPointType::Constructor,
            class
                .entry_points_by_type
                .constructor
                .into_iter()
                .map(|ep| EntryPoint {
                    selector: EntryPointSelector(felt_to_stark_felt(
                        &Felt252::try_from(ep.selector).unwrap(),
                    )),
                    offset: EntryPointOffset(ep.offset),
                })
                .collect(),
        );

        Ok(Self(Arc::new(ContractClassInner { program, entry_points_by_type })))
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClassInner {
    #[serde(deserialize_with = "deserialize_program")]
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {
    let deprecated_program = DeprecatedProgram::deserialize(deserializer)?;
    sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
}
