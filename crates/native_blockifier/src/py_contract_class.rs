use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use starknet_api::hash::StarkFelt;
use starknet_api::state::{ContractClass, EntryPoint, EntryPointType};

// A contract class as represented in Python, which is represented slightly different than
// in Starknet API.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct PyContractClass {
    pub sierra_program: Vec<StarkFelt>,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
    pub abi: String,
}

impl From<PyContractClass> for ContractClass {
    fn from(contract_class: PyContractClass) -> Self {
        Self {
            sierra_program: contract_class.sierra_program,
            // Only different is here, mapping "*_points_*" to "*_point_*".
            entry_point_by_type: contract_class.entry_points_by_type,
            abi: contract_class.abi,
        }
    }
}
