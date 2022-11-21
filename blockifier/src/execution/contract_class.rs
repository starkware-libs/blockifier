use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use starknet_api::{EntryPoint, EntryPointType, Program};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContractClass {
    // TODO(Noa, 30.12.22): Consider using a more specific field type or add a layer to
    // appropriately deserialize it.
    pub abi: serde_json::Value,
    pub program: Program,
    /// The selector of each entry point is a unique identifier in the program.
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl ContractClass {
    pub fn from_file(path: &Path) -> Result<ContractClass> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let contract_class_json = serde_json::from_reader(reader)?;
        Ok(contract_class_json)
    }
}
