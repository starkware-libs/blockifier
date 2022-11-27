use std::path::PathBuf;

use anyhow::Result;
use num_bigint::BigInt;
use starknet_api::CallData;

use crate::execution::cairo_run_utils::{execute_call_entry_point, CairoRunConfig};
use crate::execution::contract_class::ContractClass;

/// Represents a call to an entry point of a StarkNet contract.
pub struct CallEntryPoint {
    pub contract_class: ContractClass,
    pub contract_file_path: PathBuf,
    // TODO(AlonH, 15/12/2022): Change to selector.
    pub name: String,
    pub calldata: CallData,
}

impl CallEntryPoint {
    pub fn new(
        contract_class: ContractClass,
        contract_file_path: &str,
        name: &str,
        calldata: CallData,
    ) -> Self {
        let contract_file_path = PathBuf::from(contract_file_path);
        let name = name.to_string();
        Self { contract_class, contract_file_path, name, calldata }
    }

    // TODO(Adi, 27/11/2022): Change BigInt to StarkFelt.
    pub fn execute(&self) -> Result<Vec<BigInt>> {
        // Returns the output of the entry point execution.
        execute_call_entry_point(self, CairoRunConfig::default())
    }
}
