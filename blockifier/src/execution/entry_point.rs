use anyhow::Result;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use num_bigint::BigInt;
use starknet_api::CallData;

use super::cairo_run_utils::{execute_call_entry_point, CairoRunConfig};
use crate::execution::contract_class::ContractClass;

/// Represents a call to an entry point of a StarkNet contract.
pub struct CallEntryPoint {
    /// Represents a Cairo entry point of a StarkNet contract.
    pub contract_class: ContractClass,
    // TODO(AlonH, 15/12/2022): Change to selector.
    pub name: String,
    pub calldata: CallData,
}

impl CallEntryPoint {
    pub fn new(contract_class: ContractClass, name: &str, calldata: CallData) -> Self {
        let name = name.to_string();
        Self { contract_class, name, calldata }
    }

    // TODO(Adi, 27/11/2022): Change BigInt to StarkFelt.
    pub fn execute(&self) -> Result<Vec<BigInt>> {
        // Returns the output of the entry point execution.
        execute_call_entry_point(
            self,
            CairoRunConfig::default(),
            &BuiltinHintProcessor::new_empty(),
        )
    }
}
