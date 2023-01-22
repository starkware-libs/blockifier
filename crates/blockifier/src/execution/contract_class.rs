use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use starknet_api::state::{EntryPoint, EntryPointType, Program};

/// Represents a StarkNet contract class.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContractClass {
    pub program: Program,
    /// The selector of each entry point is a unique identifier in the program.
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
    // Not required for execution, thus can be omitted from the raw contract file.
    pub abi: Option<serde_json::Value>,
}

impl From<ContractClass> for starknet_api::state::ContractClass {
    fn from(contract_class: ContractClass) -> Self {
        Self {
            program: contract_class.program,
            entry_points_by_type: contract_class.entry_points_by_type,
            // ABI is not used for execution.
            abi: None,
        }
    }
}

impl From<starknet_api::state::ContractClass> for ContractClass {
    fn from(contract_class: starknet_api::state::ContractClass) -> Self {
        Self {
            program: contract_class.program,
            entry_points_by_type: contract_class.entry_points_by_type,
            // ABI is not used for execution.
            abi: None,
        }
    }
}

/// Instantiates a contract class object given a compiled contract file path.
impl TryFrom<PathBuf> for ContractClass {
    type Error = io::Error;

    fn try_from(path: PathBuf) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let raw_contract_class = serde_json::from_reader(reader)?;
        Ok(raw_contract_class)
    }
}
