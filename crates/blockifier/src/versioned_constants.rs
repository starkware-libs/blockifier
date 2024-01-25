use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use indexmap::{IndexMap, IndexSet};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use thiserror::Error;

#[cfg(test)]
#[path = "versioned_constants_test.rs"]
pub mod test;

const DEFAULT_CONSTANTS_JSON: &str = include_str!("../resources/versioned_constants.json");
static DEFAULT_CONSTANTS: Lazy<VersionedConstants> = Lazy::new(|| {
    serde_json::from_str(DEFAULT_CONSTANTS_JSON)
        .expect("Versioned constants JSON file is malformed")
});

/// Contains constants for the Blockifier that may vary between versions.
/// Additional constants in the JSON file, not used by Blockifier but included for transparency, are
/// automatically ignored during deserialization.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VersionedConstants {
    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,

    // Fee related.
    // TODO: Consider making this a struct, this will require change the way we access these
    // values.
    vm_resource_fee_cost: Arc<HashMap<String, f64>>,

    // Cairo OS constants.
    // Note: if loaded from a json file, there are some assumptions made on its structure.
    // See the struct's docstring for more details.
    starknet_os_constants: Arc<StarknetOSConstants>,
}

impl VersionedConstants {
    /// Get the constants that shipped with the current version of the Blockifier.
    /// To use custom constants, initialize the struct from a file using `try_from`.
    pub fn latest_constants() -> &'static Self {
        &DEFAULT_CONSTANTS
    }

    pub fn vm_resource_fee_cost(&self) -> &HashMap<String, f64> {
        &self.vm_resource_fee_cost
    }

    pub fn gas_cost(&self, name: &str) -> u64 {
        match self.starknet_os_constants.gas_costs.get(name) {
            Some(&cost) => cost,
            None if StarknetOSConstants::ALLOWED_GAS_COST_NAMES.contains(&name) => {
                panic!(
                    "{} is present in `StarknetOSConstants::GAS_COSTS` but not in `self`; was \
                     validation skipped?",
                    name
                )
            }
            None => {
                panic!(
                    "Only gas costs listed in `StarknetOsConstants::GAS_COSTS` should be \
                     requested, got: {}",
                    name
                )
            }
        }
    }

    #[cfg(any(feature = "testing", test))]
    pub fn create_for_account_testing() -> Self {
        let vm_resource_fee_cost = Arc::new(HashMap::from([
            (crate::abi::constants::N_STEPS_RESOURCE.to_string(), 1_f64),
            (cairo_vm::vm::runners::builtin_runner::HASH_BUILTIN_NAME.to_string(), 1_f64),
            (cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME.to_string(), 1_f64),
            (cairo_vm::vm::runners::builtin_runner::SIGNATURE_BUILTIN_NAME.to_string(), 1_f64),
            (cairo_vm::vm::runners::builtin_runner::BITWISE_BUILTIN_NAME.to_string(), 1_f64),
            (cairo_vm::vm::runners::builtin_runner::POSEIDON_BUILTIN_NAME.to_string(), 1_f64),
            (cairo_vm::vm::runners::builtin_runner::OUTPUT_BUILTIN_NAME.to_string(), 1_f64),
            (cairo_vm::vm::runners::builtin_runner::EC_OP_BUILTIN_NAME.to_string(), 1_f64),
        ]));

        Self { vm_resource_fee_cost, ..Self::create_for_testing() }
    }
}

impl TryFrom<&Path> for VersionedConstants {
    type Error = VersionedConstantsError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
    }
}

// Below, serde first deserializes the json into a regular IndexMap wrapped by the newtype
// `StarknetOSConstantsRawJSON`, then calls the `try_from` of the newtype, which handles the
// conversion into actual values.
// Assumption: if the json has a value that contains the expression "FOO * 2", then the key `FOO`
// must appear before this value in the JSON.
// FIXME: JSON doesn't guarantee order, serde seems to work for this use-case, buit there is no
// guarantee that it will stay that way. Seriously consider switching to serde_yaml/other format.
// FIXME FOLLOWUP: if we switch from JSON, we can switch to strongly typed fields, instead of an
// internal indexmap: using strongly typed fields breaks the order under serialization, making
// testing very difficult.
// TODO: consider encoding the * and + operations inside the json file, instead of hardcoded below
// in the `try_from`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(try_from = "StarknetOSConstantsRawJSON")]
pub struct StarknetOSConstants {
    gas_costs: IndexMap<String, u64>,
}

impl StarknetOSConstants {
    // List of all gas cost constants that *must* be present in the JSON file, all other consts are
    // ignored. See documentation in core/os/constants.cairo.
    const ALLOWED_GAS_COST_NAMES: [&'static str; 31] = [
        "step_gas_cost",
        "range_check_gas_cost",
        "memory_hole_gas_cost",
        "initial_gas_cost",
        "entry_point_initial_budget",
        "syscall_base_gas_cost",
        "entry_point_gas_cost",
        "fee_transfer_gas_cost",
        "transaction_gas_cost",
        "call_contract_gas_cost",
        "deploy_gas_cost",
        "get_block_hash_gas_cost",
        "get_execution_info_gas_cost",
        "library_call_gas_cost",
        "replace_class_gas_cost",
        "storage_read_gas_cost",
        "storage_write_gas_cost",
        "emit_event_gas_cost",
        "send_message_to_l1_gas_cost",
        "secp256k1_add_gas_cost",
        "secp256k1_get_point_from_x_gas_cost",
        "secp256k1_get_xy_gas_cost",
        "secp256k1_mul_gas_cost",
        "secp256k1_new_gas_cost",
        "secp256r1_add_gas_cost",
        "secp256r1_get_point_from_x_gas_cost",
        "secp256r1_get_xy_gas_cost",
        "secp256r1_mul_gas_cost",
        "secp256r1_new_gas_cost",
        "keccak_gas_cost",
        "keccak_round_cost_gas_cost",
    ];

    pub fn validate(&self) -> Result<(), StarknetConstantsSerdeError> {
        // Check that all the allowed gas consts set is contained inside the parsed consts,
        // that is, all consts in the list appeared as keys in the json file.
        for key in Self::ALLOWED_GAS_COST_NAMES {
            if !self.gas_costs.contains_key(key) {
                return Err(StarknetConstantsSerdeError::ValidationError(format!(
                    "Starknet os constants is missing the following key: {}",
                    key
                )));
            }
        }

        Ok(())
    }
}

impl TryFrom<StarknetOSConstantsRawJSON> for StarknetOSConstants {
    type Error = StarknetConstantsSerdeError;

    fn try_from(raw_json_data: StarknetOSConstantsRawJSON) -> Result<Self, Self::Error> {
        let mut gas_costs = IndexMap::new();

        let gas_cost_whitelist: IndexSet<_> =
            Self::ALLOWED_GAS_COST_NAMES.iter().copied().collect();
        for (key, value) in raw_json_data.raw_json_file_as_dict {
            if !gas_cost_whitelist.contains(key.as_str()) {
                // Ignore non-whitelist consts.
                continue;
            }

            match value {
                Value::Number(n) => {
                    let value = n
                        .as_u64()
                        .ok_or_else(|| StarknetConstantsSerdeError::OutOfRange(key.clone(), n))?;
                    gas_costs.insert(key, value);
                }
                Value::Object(obj) => {
                    // Converts:
                    // `k_1: {k_2: factor_1, k_3: factor_2}`
                    // into:
                    // k_1 = k_2 * factor_1 + k_3 * factor_2
                    // Assumption: k_2 and k_3 appeared before k_1 in the JSON.
                    let sum = obj.into_iter().try_fold(0, |acc, (inner_key, factor)| {
                        let factor = factor.as_u64().ok_or_else(|| {
                            StarknetConstantsSerdeError::OutOfRangeFactor(key.clone(), factor)
                        })?;
                        let inner_key_value = *gas_costs.get(&inner_key).ok_or_else(|| {
                            StarknetConstantsSerdeError::KeyNotFound { key: key.clone(), inner_key }
                        })?;

                        Ok(acc + inner_key_value * factor)
                    })?;
                    gas_costs.insert(key, sum);
                }
                Value::String(_) => {
                    // String consts are all non-whitelisted, ignore them.
                    continue;
                }
                _ => return Err(StarknetConstantsSerdeError::UnhandledValueType(value)),
            }
        }

        let os_constants = StarknetOSConstants { gas_costs };

        // Skip validation in testing: to test validation run validate manually.
        #[cfg(not(any(feature = "testing", test)))]
        os_constants.validate()?;

        Ok(os_constants)
    }
}

// Intermediate representation of the JSON file in order to make the deserialization easier, using a
// regular the try_from.
#[derive(Debug, Deserialize)]
struct StarknetOSConstantsRawJSON {
    #[serde(flatten)]
    raw_json_file_as_dict: IndexMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum VersionedConstantsError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("JSON file cannot be serialized into VersionedConstants: {0}")]
    ParseError(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum StarknetConstantsSerdeError {
    #[error("Validation failed: {0}")]
    ValidationError(String),
    #[error("Value {1} for key '{0}' is out of range and cannot be cast into u64")]
    OutOfRange(String, Number),
    #[error(
        "Value {1} used to create value for key '{0}' is out of range and cannot be cast into u64"
    )]
    OutOfRangeFactor(String, Value),
    #[error("Unknown key '{inner_key}' used to create value for '{key}'")]
    KeyNotFound { key: String, inner_key: String },
    #[error("Value cannot be cast into u64: {0}")]
    InvalidFactorFormat(Value),
    #[error("Unhandled value type: {0}")]
    UnhandledValueType(Value),
}
