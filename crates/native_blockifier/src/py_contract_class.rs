use blockifier::execution::contract_class::{ContractClass, ContractClassV0, ContractClassV1};
use pyo3::FromPyObject;

use crate::errors::{NativeBlockifierError, NativeBlockifierInputError, NativeBlockifierResult};

#[derive(FromPyObject)]
pub struct PyRawCompiledClass {
    pub raw_compiled_class: String,
    pub version: usize,
}

impl TryFrom<PyRawCompiledClass> for ContractClass {
    type Error = NativeBlockifierError;

    fn try_from(raw_compiled_class: PyRawCompiledClass) -> NativeBlockifierResult<Self> {
        match raw_compiled_class.version {
            0 => Ok(ContractClassV0::try_from_json_string(&raw_compiled_class.raw_compiled_class)?
                .into()),
            1 => Ok(ContractClassV1::try_from_json_string(&raw_compiled_class.raw_compiled_class)?
                .into()),
            _ => Err(NativeBlockifierError::NativeBlockifierInputError(
                NativeBlockifierInputError::UnsupportedContractClassVersion {
                    version: raw_compiled_class.version,
                },
            )),
        }
    }
}
