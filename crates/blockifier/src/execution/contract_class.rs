use std::collections::HashMap;
use std::sync::Arc;

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointType,
    Program as DeprecatedProgram,
};

use crate::execution::execution_utils::sn_api_to_cairo_vm_program;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub enum ContractClass {
    V0(ContractClassV0),
    V1(ContractClassV1),
}

/// Represents a runnable StarkNet contract class (meaning, the program is runnable by the VM).
/// We wrap the actual class in an Arc to avoid cloning the program when cloning the class.
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClassV0(pub Arc<ContractClassV0Inner>);

impl TryFrom<DeprecatedContractClass> for ContractClassV0 {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(ContractClassV0Inner {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })))
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClassV0Inner {
    #[serde(deserialize_with = "deserialize_program")]
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl From<ContractClassV0Inner> for ContractClassV0 {
    fn from(class: ContractClassV0Inner) -> Self {
        Self(Arc::new(class))
    }
}

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {
    let deprecated_program = DeprecatedProgram::deserialize(deserializer)?;
    sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
}

/// Represents a runnable StarkNet V1 contract class.
/// We wrap the actual class in an Arc to avoid cloning the program when cloning the class.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClassV1(pub Arc<ContractClassV1Inner>);

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
pub struct ContractClassV1Inner {
    // FIXME: will be replaced soon with a thinner representation.
    pub class: CasmContractClass,
}

impl TryFrom<CasmContractClass> for ContractClassV1 {
    type Error = ProgramError;

    fn try_from(class: CasmContractClass) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(ContractClassV1Inner { class })))
    }
}
