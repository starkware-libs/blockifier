use std::collections::HashMap;
use std::sync::Arc;

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::types::errors::program_errors::ProgramError;

use crate::execution::contract_class::{ContractClassV0, ContractClassV0Inner, ContractClassV1};

#[cfg(test)]
#[path = "utils_test.rs"]
pub mod test;

/// Returns a `HashMap` containing key-value pairs from `a` that are not included in `b` (if
/// a key appears in `b` with a different value, it will be part of the output).
/// Usage: Get updated items from a mapping.
pub fn subtract_mappings<K, V>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone + PartialEq,
{
    lhs.iter().filter(|(k, v)| rhs.get(k) != Some(v)).map(|(k, v)| (k.clone(), v.clone())).collect()
}

pub fn get_contract_class_v0(raw_contract_class: &str) -> Result<ContractClassV0, ProgramError> {
    let contract_class: ContractClassV0Inner = serde_json::from_str(raw_contract_class)?;
    Ok(ContractClassV0(Arc::new(contract_class)))
}

pub fn get_contract_class_v1(raw_contract_class: &str) -> Result<ContractClassV1, ProgramError> {
    let casm_contract_class: CasmContractClass = serde_json::from_str(raw_contract_class)?;
    let contract_class: ContractClassV1 = casm_contract_class.try_into()?;

    Ok(contract_class)
}
