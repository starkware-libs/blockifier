use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use cairo_felt::Felt252;
use cairo_lang_casm;
use cairo_lang_casm::hints::Hint;
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_vm::serde::deserialize_program::{
    ApTracking, BuiltinName, FlowTrackingData, HintParams, ReferenceManager,
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

use super::errors::PreExecutionError;
use crate::execution::execution_utils::{felt_to_stark_felt, sn_api_to_cairo_vm_program};

/// Represents a runnable StarkNet contract class (meaning, the program is runnable by the VM).
/// We wrap the actual class in an Arc to avoid cloning the program when cloning the class.
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractClass {
    V0(ContractClassV0),
    V1(ContractClassV1),
}
impl ContractClass {
    pub fn constructor_selector(&self) -> Option<EntryPointSelector> {
        match self {
            ContractClass::V0(class) => class.constructor_selector(),
            ContractClass::V1(class) => class.constructor_selector(),
        }
    }
}
impl From<ContractClassV0> for ContractClass {
    fn from(class: ContractClassV0) -> Self {
        Self::V0(class)
    }
}
impl From<ContractClassV1> for ContractClass {
    fn from(class: ContractClassV1) -> Self {
        Self::V1(class)
    }
}

// V0.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct ContractClassV0(pub Arc<ContractClassV0Inner>);
impl Deref for ContractClassV0 {
    type Target = ContractClassV0Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ContractClassV0 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.0.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClassV0Inner {
    #[serde(deserialize_with = "deserialize_program")]
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}
impl TryFrom<DeprecatedContractClass> for ContractClassV0 {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(ContractClassV0Inner {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })))
    }
}

// V1.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContractClassV1(pub Arc<ContractClassV1Inner>);
impl Deref for ContractClassV1 {
    type Target = ContractClassV1Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ContractClassV1 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.0.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }

    pub fn get_entry_point(
        &self,
        call: &super::entry_point::CallEntryPoint,
    ) -> Result<EntryPointV1, PreExecutionError> {
        let entry_points_of_same_type = &self.0.entry_points_by_type[&call.entry_point_type];
        let filtered_entry_points: Vec<_> = entry_points_of_same_type
            .iter()
            .filter(|ep| ep.selector == call.entry_point_selector)
            .collect();

        match &filtered_entry_points[..] {
            [] => Err(PreExecutionError::EntryPointNotFound(call.entry_point_selector)),
            [entry_point] => Ok((*entry_point).clone()),
            _ => Err(PreExecutionError::DuplicatedEntryPointSelector {
                selector: call.entry_point_selector,
                typ: call.entry_point_type,
            }),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContractClassV1Inner {
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPointV1>>,
    pub hints: HashMap<String, Hint>,
}
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct EntryPointV1 {
    pub selector: EntryPointSelector,
    pub offset: EntryPointOffset,
    pub builtins: Vec<String>,
}
impl EntryPointV1 {
    pub fn pc(&self) -> usize {
        self.offset.0
    }
}

impl TryFrom<CasmContractClass> for ContractClassV1 {
    type Error = ProgramError;

    fn try_from(class: CasmContractClass) -> Result<Self, Self::Error> {
        let data: Vec<MaybeRelocatable> = class
            .bytecode
            .into_iter()
            .map(|x| MaybeRelocatable::from(Felt252::from(x.value)))
            .collect();
        let hints: HashMap<usize, Vec<HintParams>> = class
            .hints
            .iter()
            .map(|(i, hints)| (*i, hints.iter().map(hint_to_hint_params).collect()))
            .collect();

        // Collect a sting to hint map so that the hint processor can fetch the correct [Hint]
        // for each instruction.
        let string_to_hint: HashMap<String, Hint> = class
            .hints
            .into_iter()
            .flat_map(|(_, hints)| {
                hints.iter().map(|hint| (hint.to_string(), hint.clone())).collect::<Vec<_>>()
            })
            .collect();

        // Initialize program with all builtins.
        let builtins = vec![
            BuiltinName::output,
            BuiltinName::pedersen,
            BuiltinName::range_check,
            BuiltinName::ecdsa,
            BuiltinName::bitwise,
            BuiltinName::ec_op,
            BuiltinName::poseidon,
        ];
        let main = Some(0);
        let reference_manager = ReferenceManager { references: Vec::new() };
        let identifiers = HashMap::new();
        let error_message_attributes = vec![];
        let instruction_locations = None;

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

        let mut entry_points_by_type = HashMap::new();
        entry_points_by_type.insert(
            EntryPointType::Constructor,
            convert_entrypoints_v1(class.entry_points_by_type.constructor)?,
        );
        entry_points_by_type.insert(
            EntryPointType::External,
            convert_entrypoints_v1(class.entry_points_by_type.external)?,
        );
        entry_points_by_type.insert(
            EntryPointType::L1Handler,
            convert_entrypoints_v1(class.entry_points_by_type.l1_handler)?,
        );

        Ok(Self(Arc::new(ContractClassV1Inner {
            program,
            entry_points_by_type,
            hints: string_to_hint,
        })))
    }
}

// V0 utilities.

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {
    let deprecated_program = DeprecatedProgram::deserialize(deserializer)?;
    sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
}

// V1 utilities.

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

fn convert_entrypoints_v1(
    external: Vec<CasmContractEntryPoint>,
) -> Result<Vec<EntryPointV1>, ProgramError> {
    external
        .into_iter()
        .map(|ep| -> Result<_, ProgramError> {
            Ok(EntryPointV1 {
                selector: EntryPointSelector(felt_to_stark_felt(
                    &Felt252::try_from(ep.selector).unwrap(),
                )),
                offset: EntryPointOffset(ep.offset),
                builtins: ep.builtins,
            })
        })
        .collect()
}
