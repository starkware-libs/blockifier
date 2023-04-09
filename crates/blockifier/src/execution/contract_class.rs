use std::collections::HashMap;
use std::io::Read;

use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use serde::{Deserialize, Serialize};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointType,
    Program as DeprecatedProgram,
};

use crate::execution::execution_utils::sn_api_to_cairo_vm_program;

/// Represents a runnable StarkNet contract class (meaning, the program is runnable by the VM).
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContractClass {
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl TryFrom<DeprecatedContractClass> for ContractClass {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        let class = DeprecatedContractClassWithoutAbi {
            program: class.program,
            entry_points_by_type: class.entry_points_by_type,
        };
        ContractClass::try_from(class)
    }
}

impl TryFrom<DeprecatedContractClassWithoutAbi> for ContractClass {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClassWithoutAbi) -> Result<Self, Self::Error> {
        Ok(Self {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })
    }
}

impl TryFrom<&str> for ContractClass {
    type Error = ProgramError;

    fn try_from(raw_contract_class: &str) -> Result<Self, Self::Error> {
        let deprecated_contract_class =
            DeprecatedContractClassWithoutAbi::try_from(raw_contract_class)?;
        ContractClass::try_from(deprecated_contract_class)
    }
}

#[cfg(any(feature = "testing", test))]
impl TryFrom<std::path::PathBuf> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: std::path::PathBuf) -> Result<Self, Self::Error> {
        let deprecated_contract_class = DeprecatedContractClassWithoutAbi::from(path);
        ContractClass::try_from(deprecated_contract_class)
    }
}

/// Represents a raw StarkNet contract class (non-runnable;
/// the equivalent of SN API's struct, without ABI which is not required for execution).
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct DeprecatedContractClassWithoutAbi {
    pub program: DeprecatedProgram,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl From<DeprecatedContractClassWithoutAbi> for DeprecatedContractClass {
    fn from(contract_class: DeprecatedContractClassWithoutAbi) -> Self {
        Self {
            program: contract_class.program,
            entry_points_by_type: contract_class.entry_points_by_type,
            abi: None,
        }
    }
}

impl TryFrom<&str> for DeprecatedContractClassWithoutAbi {
    type Error = serde_json::Error;

    fn try_from(raw_contract_class: &str) -> Result<Self, Self::Error> {
        let mut raw_contract_class: serde_json::Value = serde_json::from_str(raw_contract_class)?;

        // ABI is not required for execution.
        raw_contract_class
            .as_object_mut()
            .expect("A compiled contract must be a JSON object.")
            .insert("abi".to_string(), serde_json::Value::Null);

        let deprecated_contract_class: DeprecatedContractClassWithoutAbi =
            serde_json::from_value(raw_contract_class)?;
        Ok(deprecated_contract_class)
    }
}

#[cfg(any(feature = "testing", test))]
impl From<std::path::PathBuf> for DeprecatedContractClassWithoutAbi {
    fn from(path: std::path::PathBuf) -> Self {
        let mut file =
            std::fs::File::open(&path).unwrap_or_else(|_| panic!("File {path:?} does not exist."));
        let mut raw_contract_class = String::new();
        file.read_to_string(&mut raw_contract_class).expect("Malformed class JSON.");

        DeprecatedContractClassWithoutAbi::try_from(raw_contract_class.as_str())
            .expect("Malformed class JSON.")
    }
}
