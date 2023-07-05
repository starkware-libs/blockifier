use std::collections::HashMap;
use std::sync::Arc;

use blockifier::execution::contract_class::{
    ContractClass, ContractClassV1, ContractClassV1Inner, EntryPointV1,
};
use cairo_vm::types::program::Program;
use pyo3::FromPyObject;
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{EntryPointOffset, EntryPointType};

use crate::errors::{NativeBlockifierError, NativeBlockifierResult};
use crate::py_utils::PyFelt;

#[derive(Eq, FromPyObject, Hash, PartialEq)]
pub enum PyEntryPointType {
    External(usize),
    L1Handler(usize),
    Constructor(usize),
}

impl From<PyEntryPointType> for EntryPointType {
    fn from(value: PyEntryPointType) -> Self {
        match value {
            PyEntryPointType::External(_) => EntryPointType::External,
            PyEntryPointType::L1Handler(_) => EntryPointType::L1Handler,
            PyEntryPointType::Constructor(_) => EntryPointType::Constructor,
        }
    }
}

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

#[derive(FromPyObject)]
pub struct PyCompiledClassBase {
    pub entry_points_by_type: HashMap<PyEntryPointType, Vec<PyCompiledClassEntryPoint>>,
}

impl TryFrom<PyCompiledClassBase> for ContractClass {
    type Error = NativeBlockifierError;

    fn try_from(py_value: PyCompiledClassBase) -> NativeBlockifierResult<Self> {
        let mut entry_points_by_type = HashMap::new();
        for (entry_point_type, entry_points) in py_value.entry_points_by_type {
            entry_points_by_type.insert(
                EntryPointType::from(entry_point_type),
                entry_points
                    .into_iter()
                    .map(EntryPointV1::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        Ok(ContractClass::V1(ContractClassV1(Arc::new(ContractClassV1Inner {
            program: Program::default(),
            entry_points_by_type,
            hints: HashMap::new(),
        }))))
    }
}
