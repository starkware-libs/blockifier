use std::collections::HashMap;

use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointType,
    Program as DeprecatedProgram,
};

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

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {
    let deprecated_program = DeprecatedProgram::deserialize(deserializer)?;
    sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
}
