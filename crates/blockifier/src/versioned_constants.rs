use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

use cairo_vm::vm::runners::builtin_runner;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use indexmap::{IndexMap, IndexSet};
use once_cell::sync::Lazy;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::deprecated_syscalls::DeprecatedSyscallSelector;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::transaction_types::TransactionType;

#[cfg(test)]
#[path = "versioned_constants_test.rs"]
pub mod test;

const DEFAULT_CONSTANTS_JSON: &str = include_str!("../resources/versioned_constants.json");
static DEFAULT_CONSTANTS: Lazy<VersionedConstants> = Lazy::new(|| {
    serde_json::from_str(DEFAULT_CONSTANTS_JSON)
        .expect("Versioned constants json file is malformed")
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

    // Resources.
    os_resources: Arc<OsResources>,

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

    /// Returns the initial gas of any transaction to run with.
    pub fn tx_initial_gas(&self) -> u64 {
        let os_consts = &self.starknet_os_constants;

        os_consts.gas_costs["initial_gas_cost"] - os_consts.gas_costs["transaction_gas_cost"]
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

    pub fn resources_for_tx_type(&self, tx_type: &TransactionType) -> &VmExecutionResources {
        self.os_resources.resources_for_tx_type(tx_type)
    }

    /// Calculates the additional resources needed for the OS to run the given syscalls;
    /// i.e., the resources of the Starknet OS function `execute_syscalls`.
    pub fn get_additional_os_resources(
        &self,
        syscall_counter: &SyscallCounter,
        tx_type: TransactionType,
        calldata_length: usize,
    ) -> Result<VmExecutionResources, TransactionExecutionError> {
        self.os_resources.get_additional_os_resources(syscall_counter, tx_type, calldata_length)
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

#[derive(Debug, Deserialize, Clone, Default)]
// Serde trick for adding validations via a customr deserializer, without forgoing the derive.
// See: https://github.com/serde-rs/serde/issues/1220.
#[serde(remote = "Self")]
pub struct OsResources {
    // Mapping from every syscall to its execution resources in the OS (e.g., amount of Cairo
    // steps).
    // TODO(Arni, 14/6/2023): Update `GetBlockHash` values.
    // TODO(ilya): Consider moving the resources of a keccak round to a seperate dict.
    execute_syscalls: HashMap<DeprecatedSyscallSelector, VmExecutionResources>,
    // Mapping from every transaction to its extra execution resources in the OS,
    // i.e., resources that don't count during the execution itself.
    execute_txs_inner: HashMap<TransactionType, VmExecutionResources>,
}

impl OsResources {
    fn get_additional_os_resources(
        &self,
        syscall_counter: &SyscallCounter,
        tx_type: TransactionType,
        _calldata_length: usize,
    ) -> Result<VmExecutionResources, TransactionExecutionError> {
        // TODO(Noa, 21/01/24): Use calldata_length.
        let mut os_additional_vm_resources = VmExecutionResources::default();
        for (syscall_selector, count) in syscall_counter {
            let syscall_resources =
                self.execute_syscalls.get(syscall_selector).unwrap_or_else(|| {
                    panic!("OS resources of syscall '{syscall_selector:?}' are unknown.")
                });
            os_additional_vm_resources += &(syscall_resources * *count);
        }

        // Calculates the additional resources needed for the OS to run the given transaction;
        // i.e., the resources of the Starknet OS function `execute_transactions_inner`.
        // Also adds the resources needed for the fee transfer execution, performed in the end·
        // of every transaction.
        let os_resources = self.resources_for_tx_type(&tx_type);
        Ok(&os_additional_vm_resources + os_resources)
    }

    fn resources_for_tx_type(&self, tx_type: &TransactionType) -> &VmExecutionResources {
        self.execute_txs_inner
            .get(tx_type)
            .unwrap_or_else(|| panic!("should contain transaction type '{tx_type:?}'."))
    }
}

impl<'de> Deserialize<'de> for OsResources {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let os_resources = Self::deserialize(deserializer)?;

        // Validations.

        for tx_type in TransactionType::iter() {
            if !os_resources.execute_txs_inner.contains_key(&tx_type) {
                return Err(DeserializationError::custom(format!(
                    "ValidationError: os_resources.execute_tx_inner is missing transaction_type: \
                     {tx_type:?}"
                )));
            }
        }

        for syscall_handler in DeprecatedSyscallSelector::iter() {
            if !os_resources.execute_syscalls.contains_key(&syscall_handler) {
                return Err(DeserializationError::custom(format!(
                    "ValidationError: os_resources.execute_syscalls are missing syscall handler: \
                     {syscall_handler:?}"
                )));
            }
        }

        let known_builtin_names: HashSet<&str> = HashSet::from([
            builtin_runner::OUTPUT_BUILTIN_NAME,
            builtin_runner::HASH_BUILTIN_NAME,
            builtin_runner::RANGE_CHECK_BUILTIN_NAME,
            builtin_runner::SIGNATURE_BUILTIN_NAME,
            builtin_runner::BITWISE_BUILTIN_NAME,
            builtin_runner::EC_OP_BUILTIN_NAME,
            builtin_runner::KECCAK_BUILTIN_NAME,
            builtin_runner::POSEIDON_BUILTIN_NAME,
            builtin_runner::SEGMENT_ARENA_BUILTIN_NAME,
        ]);
        let all_resources =
            os_resources.execute_syscalls.values().chain(os_resources.execute_txs_inner.values());

        for resources in all_resources {
            for builtin_name in resources.builtin_instance_counter.keys() {
                if !known_builtin_names.contains(builtin_name.as_str()) {
                    return Err(DeserializationError::custom(format!(
                        "ValidationError: unknown os resource {builtin_name}"
                    )));
                }
            }
        }

        Ok(os_resources)
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
    // See documentation in core/os/constants.cairo.
    const ALLOWED_GAS_COST_NAMES: [&'static str; 31] = [
        "step_gas_cost",
        "range_check_gas_cost",
        "memory_hole_gas_cost",
        // An estimation of the initial gas for a transaction to run with. This solution is
        // temporary and this value will become a field of the transaction.
        "initial_gas_cost",
        // ** Compiler gas costs **
        "entry_point_initial_budget",
        // The initial gas budget for a system call (this value is hard-coded by the compiler).
        // This needs to be high enough to cover OS costs in the case of failure due to out of gas.
        "syscall_base_gas_cost",
        // ** OS gas costs **
        "entry_point_gas_cost",
        "fee_transfer_gas_cost",
        "transaction_gas_cost",
        // ** Required gas for each syscall **
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
        // Check that all gas cost constants are present.
        // Other consts are unused.
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

    fn try_from(intermediate: StarknetOSConstantsRawJSON) -> Result<Self, Self::Error> {
        let mut gas_costs = IndexMap::new();

        let gas_cost_whitelist: IndexSet<_> =
            Self::ALLOWED_GAS_COST_NAMES.iter().copied().collect();
        for (key, value) in intermediate.regular {
            if !gas_cost_whitelist.contains(key.as_str()) {
                // Ignore unused consts for now.
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
                    // String consts are all unused at the moment.
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
    regular: IndexMap<String, Value>,
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
