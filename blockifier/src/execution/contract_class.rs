use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use starknet_api::state::{EntryPoint, EntryPointType, Program};

/// Represents a StarkNet contract class.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContractClass {
    // TODO(Noa, 30/12/22): Consider using a more specific field type or add a layer to
    // appropriately deserialize it.
    pub program: Program,
    /// The selector of each entry point is a unique identifier in the program.
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
    /// Not required for execution, thus can be omitted from the raw contract file.
    pub abi: Option<serde_json::Value>,
}

impl ContractClass {
    /// Instantiates a contract class object given a compiled contract file path.
    pub fn from_file(path: &Path) -> Result<ContractClass> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let raw_contract_class = serde_json::from_reader(reader)?;
        Ok(raw_contract_class)
    }
}

impl From<ContractClass> for starknet_api::state::ContractClass {
    fn from(contract_class: ContractClass) -> Self {
        Self {
            // The sequencer make no use of this field.
            abi: None,

            program: contract_class.program,
            entry_points_by_type: contract_class.entry_points_by_type,
        }
    }
}
