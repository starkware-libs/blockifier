use std::collections::HashMap;
use std::sync::Arc;

use blockifier::execution::contract_class::{
    ContractClass, ContractClassV0, ContractClassV0Inner, ContractClassV1, ContractClassV1Inner,
    EntryPointV1,
};
use cairo_lang_casm;
use cairo_lang_casm::hints::Hint;
use cairo_vm::felt::Felt252;
use cairo_vm::serde::deserialize_program::{
    ApTracking, FlowTrackingData, HintLocation, HintParams, Identifier, InputFile,
    InstructionLocation, Location, Member, OffsetValue, Reference, ReferenceManager, ValueAddress,
};
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use num_bigint::{BigInt, BigUint};
use pyo3::FromPyObject;
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{EntryPoint, EntryPointOffset, EntryPointType};

use crate::errors::{NativeBlockifierError, NativeBlockifierInputError, NativeBlockifierResult};
use crate::py_utils::{builtin_name_from_str, to_entry_point_type, PyFelt};

#[derive(Eq, FromPyObject, Hash, PartialEq)]
pub struct PyEntryPointType(#[pyo3(from_py_with = "to_entry_point_type")] pub EntryPointType);

#[derive(FromPyObject)]
pub struct PyCompiledClassEntryPoint {
    pub selector: PyFelt,
    pub offset: PyFelt,
    pub builtins: Option<Vec<String>>,
}

impl TryFrom<PyCompiledClassEntryPoint> for EntryPointV1 {
    type Error = NativeBlockifierError;

    fn try_from(value: PyCompiledClassEntryPoint) -> NativeBlockifierResult<Self> {
        Ok(EntryPointV1 {
            selector: EntryPointSelector(value.selector.0),
            offset: EntryPointOffset(usize::try_from(value.offset.0)?),
            builtins: value.builtins.unwrap_or_default(),
        })
    }
}

impl TryFrom<PyCompiledClassEntryPoint> for EntryPoint {
    type Error = NativeBlockifierError;

    fn try_from(value: PyCompiledClassEntryPoint) -> NativeBlockifierResult<Self> {
        Ok(EntryPoint {
            selector: EntryPointSelector(value.selector.0),
            offset: EntryPointOffset(usize::try_from(value.offset.0)?),
        })
    }
}

#[derive(Eq, FromPyObject, Hash, PartialEq, Debug)]
pub struct PyScopedName {
    // TODO: should we get the separator from python?
    // pub separator: String,
    pub path: Vec<String>,
}

impl ToString for PyScopedName {
    fn to_string(&self) -> String {
        self.path.join(".")
    }
}

#[derive(FromPyObject)]
pub struct PyRegTrackingData {
    pub group: usize,
    pub offset: usize,
}

#[derive(FromPyObject)]
pub struct PyFlowTrackingDataActual {
    pub ap_tracking: PyRegTrackingData,
    pub reference_ids: HashMap<PyScopedName, usize>,
}

#[derive(FromPyObject)]
pub struct PyCairoHint {
    pub code: String,
    pub accessible_scopes: Vec<PyScopedName>,
    pub flow_tracking_data: PyFlowTrackingDataActual,
}

#[derive(FromPyObject, Debug)]
pub struct PyOtherDefinition {
    #[pyo3(attribute("TYPE"))]
    pub type_: String,
}

#[derive(FromPyObject, Debug)]
pub struct PyConstDefintion {
    #[pyo3(attribute("TYPE"))]
    pub type_: String,
    pub value: BigInt,
}

#[derive(FromPyObject, Debug)]
pub struct PyMemberDefintion {
    #[pyo3(attribute("TYPE"))]
    pub type_: String,
    // TODO:
    // pub cairo_type: String,
    pub offset: usize,
}

#[derive(FromPyObject, Debug)]
pub struct PyStructDefinition {
    #[pyo3(attribute("TYPE"))]
    pub type_: String,
    pub full_name: PyScopedName,
    pub members: HashMap<String, PyMemberDefintion>,
}

#[derive(FromPyObject, Debug)]
pub struct PyLabelDefintion {
    #[pyo3(attribute("TYPE"))]
    pub type_: String,
    pub pc: usize,
}

#[derive(FromPyObject, Debug)]
pub struct PyReferenceDefintion {
    #[pyo3(attribute("TYPE"))]
    pub type_: String,
    pub full_name: PyScopedName,
}

#[derive(FromPyObject, Debug)]
pub enum PyIdentifierDefinition {
    Const(PyConstDefintion),
    Struct(PyStructDefinition),
    Label(PyLabelDefintion),
    Reference(PyReferenceDefintion),
    Other(PyOtherDefinition),
}

impl From<PyIdentifierDefinition> for Identifier {
    fn from(value: PyIdentifierDefinition) -> Self {
        // TODO: some identifiers have cairo_type.
        match value {
            PyIdentifierDefinition::Const(id) => Identifier {
                pc: None,
                type_: Some(id.type_),
                value: Some(Felt252::from(id.value)),
                full_name: None,
                members: None,
                cairo_type: None,
            },
            PyIdentifierDefinition::Label(id) => Identifier {
                pc: Some(id.pc),
                type_: Some(id.type_),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
            },
            PyIdentifierDefinition::Reference(id) => Identifier {
                pc: None,
                type_: Some(id.type_),
                value: None,
                full_name: Some(id.full_name.to_string()),
                members: None,
                cairo_type: None,
            },
            PyIdentifierDefinition::Struct(id) => Identifier {
                pc: None,
                type_: Some(id.type_),
                value: None,
                full_name: Some(id.full_name.to_string()),
                members: Some(
                    id.members
                        .into_iter()
                        .map(|(k, v)| {
                            (k, Member { cairo_type: String::from(""), offset: v.offset })
                        })
                        .collect(),
                ),
                cairo_type: None,
            },
            PyIdentifierDefinition::Other(id) => Identifier {
                pc: None,
                type_: Some(id.type_),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
            },
        }
    }
}

#[derive(FromPyObject)]
pub struct PyIdentifierManager {
    pub dict: HashMap<PyScopedName, PyIdentifierDefinition>,
}

#[derive(FromPyObject)]
pub struct PyInputFile {
    pub filename: Option<String>,
}

#[derive(FromPyObject)]
pub struct PyLocation {
    pub end_line: u32,
    pub end_col: u32,
    pub input_file: PyInputFile,
    // TODO:
    // pub parent_location: Option<(Box<PyLocation>, String)>,
    pub start_line: u32,
    pub start_col: u32,
}

impl From<PyLocation> for Location {
    fn from(value: PyLocation) -> Self {
        Location {
            end_line: value.end_line,
            end_col: value.end_col,
            input_file: InputFile { filename: value.input_file.filename.unwrap_or_default() },
            parent_location: None,
            start_line: value.start_line,
            start_col: value.start_col,
        }
    }
}

#[derive(FromPyObject)]
pub struct PyHintLocation {
    pub location: PyLocation,
    pub n_prefix_newlines: u32,
}

#[derive(FromPyObject)]
pub struct PyInstructionLocation {
    pub inst: PyLocation,
    pub hints: Vec<Option<PyHintLocation>>,
}

impl From<PyInstructionLocation> for InstructionLocation {
    fn from(value: PyInstructionLocation) -> Self {
        InstructionLocation {
            inst: Location::from(value.inst),
            hints: value
                .hints
                .into_iter()
                .filter(|h| h.is_some())
                .map(|h| {
                    let h = h.unwrap();
                    HintLocation {
                        location: Location::from(h.location),
                        n_prefix_newlines: h.n_prefix_newlines,
                    }
                })
                .collect(),
        }
    }
}

#[derive(FromPyObject)]
pub struct PyDebugInfo {
    pub instruction_locations: HashMap<usize, PyInstructionLocation>,
}

#[derive(FromPyObject)]
pub struct PyReference {
    pub ap_tracking_data: PyRegTrackingData,
    pub pc: usize,
    // TODO:
    // #[serde(deserialize_with = "deserialize_value_address")]
    // #[serde(rename(deserialize = "value"))]
    // pub value_address: ValueAddress,
}

#[derive(FromPyObject)]
pub struct PyReferenceManager {
    pub references: Vec<PyReference>,
}

#[derive(FromPyObject)]
pub struct PyProgram {
    pub data: Vec<BigUint>,
    pub builtins: Vec<String>,
    pub hints: HashMap<usize, Vec<PyCairoHint>>,
    pub main: Option<usize>,
    pub identifiers: PyIdentifierManager,
    pub reference_manager: PyReferenceManager,
    pub debug_info: Option<PyDebugInfo>,
}

impl TryFrom<PyProgram> for Program {
    type Error = NativeBlockifierError;

    fn try_from(value: PyProgram) -> NativeBlockifierResult<Self> {
        // TODO: assert prime value.

        // let start = match program_json.identifiers.get("__main__.__start__") {
        //     Some(identifier) => identifier.pc,
        //     None => None,
        // };
        // let end = match program_json.identifiers.get("__main__.__end__") {
        //     Some(identifier) => identifier.pc,
        //     None => None,
        // };

        let builtins =
            value.builtins.into_iter().map(builtin_name_from_str).collect::<Result<Vec<_>, _>>()?;
        let data = value.data.iter().map(|x| MaybeRelocatable::from(Felt252::from(x))).collect();
        let hints = value
            .hints
            .iter()
            .map(|(int, hint_vec)| {
                (
                    *int,
                    hint_vec
                        .iter()
                        .map(|h| HintParams {
                            code: h.code.to_string(),
                            accessible_scopes: h
                                .accessible_scopes
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                            flow_tracking_data: FlowTrackingData {
                                ap_tracking: ApTracking {
                                    group: h.flow_tracking_data.ap_tracking.group,
                                    offset: h.flow_tracking_data.ap_tracking.offset,
                                },
                                reference_ids: h
                                    .flow_tracking_data
                                    .reference_ids
                                    .iter()
                                    .map(|(k, v)| (k.to_string(), *v))
                                    .collect(),
                            },
                        })
                        .collect(),
                )
            })
            .collect();
        let error_message_attributes = Vec::new();

        // TODO: implement From<PyRegTracingData> for ApTracking
        // TODO: implement From<PyReference> for Reference
        let reference_manager = ReferenceManager {
            references: value
                .reference_manager
                .references
                .into_iter()
                .map(|r| Reference {
                    ap_tracking_data: ApTracking {
                        group: r.ap_tracking_data.group,
                        offset: r.ap_tracking_data.offset,
                    },
                    pc: Some(r.pc),
                    value_address: ValueAddress {
                        dereference: false,
                        offset1: OffsetValue::Value(0),
                        offset2: OffsetValue::Value(0),
                        value_type: String::from(""),
                    },
                })
                .collect(),
        };

        let identifiers: HashMap<String, Identifier> = value
            .identifiers
            .dict
            .into_iter()
            .map(|(k, v)| (k.to_string(), Identifier::from(v)))
            .collect();

        let instruction_locations = value.debug_info.map(|info| {
            info.instruction_locations
                .into_iter()
                .map(|(k, v)| (k, InstructionLocation::from(v)))
                .collect()
        });

        Ok(Program::new(
            builtins,
            data,
            value.main,
            hints,
            reference_manager,
            identifiers,
            error_message_attributes,
            instruction_locations,
        )?)
    }
}

#[derive(FromPyObject)]
pub struct PyCompiledClass {
    pub entry_points_by_type: HashMap<PyEntryPointType, Vec<PyCompiledClassEntryPoint>>,
    pub hints: Vec<String>,
}

#[derive(FromPyObject)]
pub struct PyDeprecatedCompiledClass {
    pub entry_points_by_type: HashMap<PyEntryPointType, Vec<PyCompiledClassEntryPoint>>,
}

// #[derive(FromPyObject)]
// pub enum PyCompiledClassBase {
//     V1(PyCompiledClass),
//     V0(PyDeprecatedCompiledClass),
// }

#[derive(FromPyObject)]
pub struct PyCompiledClassBase {
    pub entry_points_by_type: HashMap<PyEntryPointType, Vec<PyCompiledClassEntryPoint>>,
}

// impl TryFrom<PyCompiledClassBase> for ContractClass {
//     type Error = NativeBlockifierError;

//     fn try_from(py_value: PyCompiledClassBase) -> NativeBlockifierResult<Self> {
//         let mut entry_points_by_type = HashMap::new();
//         for (entry_point_type, entry_points) in py_value.entry_points_by_type {
//             entry_points_by_type.insert(
//                 entry_point_type.0,
//                 entry_points
//                     .into_iter()
//                     .map(EntryPoint::try_from)
//                     .collect::<Result<Vec<_>, _>>()?,
//             );
//         }

//         Ok(ContractClass::V0(ContractClassV0(Arc::new(ContractClassV0Inner {
//             program: Program::try_from(py_value.program)?,
//             entry_points_by_type,
//         }))))
//     }
// }

// #[derive(FromPyObject)]
// pub struct PyRawCompiledClass {
//     pub compiled_class: PyCompiledClassBase,
//     // Assuming DeprecatedCompiledClass python object. Should support also CompiledClass.
//     pub raw_program: String,
// }

#[derive(FromPyObject)]
pub struct PyRawCompiledClass {
    // pub compiled_class: PyCompiledClassBase,
    pub raw_compiled_class: String,
    // Assuming DeprecatedCompiledClass python object. Should support also CompiledClass.
    pub version: usize,
    // pub raw_program: String,
}

impl TryFrom<PyRawCompiledClass> for ContractClass {
    type Error = NativeBlockifierError;

    fn try_from(py_value: PyRawCompiledClass) -> NativeBlockifierResult<Self> {
        // log::debug!("------ Got class with version {:?}", py_value.version);
        // let mut entry_points_by_type = HashMap::new();
        // for (entry_point_type, entry_points) in py_value.compiled_class.entry_points_by_type {
        //     entry_points_by_type.insert(
        //         entry_point_type.0,
        //         entry_points
        //             .into_iter()
        //             .map(EntryPoint::try_from)
        //             .collect::<Result<Vec<_>, _>>()?,
        //     );
        // }

        // Ok(ContractClass::V0(ContractClassV0(Arc::new(ContractClassV0Inner {
        //     program: Program::from_bytes(py_value.raw_program.as_bytes(), None)?,
        //     entry_points_by_type,
        // }))))
        log::debug!("------ Got class with version {:?}", py_value.version);
        match py_value.version {
            0 => Ok(ContractClassV0::try_from_json_string(&py_value.raw_compiled_class)?.into()),
            1 => Ok(ContractClassV1::try_from_json_string(&py_value.raw_compiled_class)?.into()),
            _ => Err(NativeBlockifierError::NativeBlockifierInputError(
                NativeBlockifierInputError::InvalidInput,
            )),
        }
    }
}
