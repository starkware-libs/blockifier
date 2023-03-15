use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointType, Program,
};

use crate::collections::HashMap;

/// Represents a StarkNet contract class.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContractClass {
    pub program: Program,
    /// The selector of each entry point is a unique identifier in the program.
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
    // Not required for execution, thus can be omitted from the raw contract file.
    pub abi: Option<serde_json::Value>,
}

impl From<ContractClass> for DeprecatedContractClass {
    fn from(contract_class: ContractClass) -> Self {
        Self {
            program: contract_class.program,
            entry_points_by_type: contract_class.entry_points_by_type,
            // ABI is not used for execution.
            abi: None,
        }
    }
}

impl From<DeprecatedContractClass> for ContractClass {
    fn from(contract_class: DeprecatedContractClass) -> Self {
        Self {
            program: contract_class.program,
            entry_points_by_type: contract_class.entry_points_by_type,
            // ABI is not used for execution.
            abi: None,
        }
    }
}
