use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

use cairo_vm::vm::runners::builtin_runner;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use indexmap::{IndexMap, IndexSet};
use num_rational::Ratio;
use once_cell::sync::Lazy;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::execution::deprecated_syscalls::hint_processor::SyscallCounter;
use crate::execution::errors::PostExecutionError;
use crate::execution::execution_utils::poseidon_hash_many_cost;
use crate::execution::syscalls::SyscallSelector;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::transaction_types::TransactionType;
use crate::utils;

#[cfg(test)]
#[path = "versioned_constants_test.rs"]
pub mod test;

const DEFAULT_CONSTANTS_JSON: &str = include_str!("../resources/versioned_constants.json");
static DEFAULT_CONSTANTS: Lazy<VersionedConstants> = Lazy::new(|| {
    serde_json::from_str(DEFAULT_CONSTANTS_JSON)
        .expect("Versioned constants JSON file is malformed")
});

pub type ResourceCost = Ratio<u128>;

/// Contains constants for the Blockifier that may vary between versions.
/// Additional constants in the JSON file, not used by Blockifier but included for transparency, are
/// automatically ignored during deserialization.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VersionedConstants {
    // Limits.
    #[serde(default = "EventLimits::max")]
    pub tx_event_limits: EventLimits,
    pub invoke_tx_max_n_steps: u32,
    #[serde(default)]
    pub l2_resource_gas_costs: L2ResourceGasCosts,
    pub max_recursion_depth: usize,
    pub validate_max_n_steps: u32,

    // Cairo OS constants.
    // Note: if loaded from a json file, there are some assumptions made on its structure.
    // See the struct's docstring for more details.
    pub os_constants: Arc<OSConstants>,

    // Resources.
    os_resources: Arc<OsResources>,

    // Fee related.
    // TODO: Consider making this a struct, this will require change the way we access these
    // values.
    vm_resource_fee_cost: Arc<HashMap<String, ResourceCost>>,
}

impl VersionedConstants {
    /// Get the constants that shipped with the current version of the Blockifier.
    /// To use custom constants, initialize the struct from a file using `try_from`.
    pub fn latest_constants() -> &'static Self {
        &DEFAULT_CONSTANTS
    }

    /// Returns the initial gas of any transaction to run with.
    pub fn tx_initial_gas(&self) -> u64 {
        let os_consts = &self.os_constants;
        os_consts.gas_costs.initial_gas_cost - os_consts.gas_costs.transaction_gas_cost
    }

    pub fn vm_resource_fee_cost(&self) -> &HashMap<String, ResourceCost> {
        &self.vm_resource_fee_cost
    }

    pub fn os_resources_for_tx_type(
        &self,
        tx_type: &TransactionType,
        calldata_length: usize,
    ) -> ExecutionResources {
        self.os_resources.resources_for_tx_type(tx_type, calldata_length)
    }

    pub fn os_kzg_da_resources(&self, data_segment_length: usize) -> ExecutionResources {
        self.os_resources.os_kzg_da_resources(data_segment_length)
    }

    pub fn get_additional_os_tx_resources(
        &self,
        tx_type: TransactionType,
        calldata_length: usize,
        data_segment_length: usize,
        use_kzg_da: bool,
    ) -> Result<ExecutionResources, TransactionExecutionError> {
        self.os_resources.get_additional_os_tx_resources(
            tx_type,
            calldata_length,
            data_segment_length,
            use_kzg_da,
        )
    }

    pub fn get_additional_os_syscall_resources(
        &self,
        syscall_counter: &SyscallCounter,
    ) -> Result<ExecutionResources, PostExecutionError> {
        self.os_resources.get_additional_os_syscall_resources(syscall_counter)
    }

    pub fn get_validate_block_number_rounding(&self) -> u64 {
        self.os_constants.validate_rounding_consts.validate_block_number_rounding
    }

    pub fn get_validate_timestamp_rounding(&self) -> u64 {
        self.os_constants.validate_rounding_consts.validate_timestamp_rounding
    }

    #[cfg(any(feature = "testing", test))]
    pub fn create_for_account_testing() -> Self {
        let vm_resource_fee_cost = Arc::new(HashMap::from([
            (crate::abi::constants::N_STEPS_RESOURCE.to_string(), ResourceCost::from_integer(1)),
            (
                cairo_vm::vm::runners::builtin_runner::HASH_BUILTIN_NAME.to_string(),
                ResourceCost::from_integer(1),
            ),
            (
                cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME.to_string(),
                ResourceCost::from_integer(1),
            ),
            (
                cairo_vm::vm::runners::builtin_runner::SIGNATURE_BUILTIN_NAME.to_string(),
                ResourceCost::from_integer(1),
            ),
            (
                cairo_vm::vm::runners::builtin_runner::BITWISE_BUILTIN_NAME.to_string(),
                ResourceCost::from_integer(1),
            ),
            (
                cairo_vm::vm::runners::builtin_runner::POSEIDON_BUILTIN_NAME.to_string(),
                ResourceCost::from_integer(1),
            ),
            (
                cairo_vm::vm::runners::builtin_runner::OUTPUT_BUILTIN_NAME.to_string(),
                ResourceCost::from_integer(1),
            ),
            (
                cairo_vm::vm::runners::builtin_runner::EC_OP_BUILTIN_NAME.to_string(),
                ResourceCost::from_integer(1),
            ),
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct L2ResourceGasCosts {
    // TODO(barak, 18/03/2024): Once we start charging per byte change to milligas_per_data_byte,
    // divide the value by 32 in the JSON file.
    pub gas_per_data_felt: ResourceCost,
    pub event_key_factor: ResourceCost,
    pub gas_per_code_byte: ResourceCost,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct EventLimits {
    pub max_data_length: usize,
    pub max_keys_length: usize,
    pub max_n_emitted_events: usize,
}

impl EventLimits {
    fn max() -> Self {
        Self {
            max_data_length: usize::MAX,
            max_keys_length: usize::MAX,
            max_n_emitted_events: usize::MAX,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
// Serde trick for adding validations via a customr deserializer, without forgoing the derive.
// See: https://github.com/serde-rs/serde/issues/1220.
#[serde(remote = "Self")]
pub struct OsResources {
    // Mapping from every syscall to its execution resources in the OS (e.g., amount of Cairo
    // steps).
    // TODO(Arni, 14/6/2023): Update `GetBlockHash` values.
    // TODO(ilya): Consider moving the resources of a keccak round to a seperate dict.
    execute_syscalls: HashMap<SyscallSelector, ExecutionResources>,
    // Mapping from every transaction to its extra execution resources in the OS,
    // i.e., resources that don't count during the execution itself.
    // For each transaction the OS uses a constant amount of VM resources, and an
    // additional variable amount that depends on the calldata length.
    execute_txs_inner: HashMap<TransactionType, ResourcesByVersion>,

    // Resources needed for the OS to compute the KZG commitment info, as a factor of the data
    // segment length. Does not include poseidon_hash_many cost.
    compute_os_kzg_commitment_info: ExecutionResources,
}

impl OsResources {
    pub fn validate<'de, D: Deserializer<'de>>(
        &self,
    ) -> Result<(), <D as Deserializer<'de>>::Error> {
        for tx_type in TransactionType::iter() {
            if !self.execute_txs_inner.contains_key(&tx_type) {
                return Err(DeserializationError::custom(format!(
                    "ValidationError: os_resources.execute_tx_inner is missing transaction_type: \
                     {tx_type:?}"
                )));
            }
        }

        for syscall_handler in SyscallSelector::iter() {
            if !self.execute_syscalls.contains_key(&syscall_handler) {
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

        let execution_resources = self
            .execute_txs_inner
            .values()
            .flat_map(|resources_vector| {
                [
                    &resources_vector.deprecated_resources.constant,
                    &resources_vector.deprecated_resources.calldata_factor,
                ]
            })
            .chain(self.execute_syscalls.values())
            .chain(std::iter::once(&self.compute_os_kzg_commitment_info));
        let builtin_names =
            execution_resources.flat_map(|resources| resources.builtin_instance_counter.keys());
        for builtin_name in builtin_names {
            if !(known_builtin_names.contains(builtin_name.as_str())) {
                return Err(DeserializationError::custom(format!(
                    "ValidationError: unknown os resource {builtin_name}"
                )));
            }
        }

        Ok(())
    }
    /// Calculates the additional resources needed for the OS to run the given transaction;
    /// i.e., the resources of the Starknet OS function `execute_transactions_inner`.
    /// Also adds the resources needed for the fee transfer execution, performed in the end·
    /// of every transaction.
    fn get_additional_os_tx_resources(
        &self,
        tx_type: TransactionType,
        calldata_length: usize,
        data_segment_length: usize,
        use_kzg_da: bool,
    ) -> Result<ExecutionResources, TransactionExecutionError> {
        let mut os_additional_vm_resources = self.resources_for_tx_type(&tx_type, calldata_length);

        if use_kzg_da {
            os_additional_vm_resources += &self.os_kzg_da_resources(data_segment_length);
        }

        Ok(os_additional_vm_resources)
    }

    /// Calculates the additional resources needed for the OS to run the given syscalls;
    /// i.e., the resources of the Starknet OS function `execute_syscalls`.
    fn get_additional_os_syscall_resources(
        &self,
        syscall_counter: &SyscallCounter,
    ) -> Result<ExecutionResources, PostExecutionError> {
        let mut os_additional_resources = ExecutionResources::default();
        for (syscall_selector, count) in syscall_counter {
            let syscall_resources =
                self.execute_syscalls.get(syscall_selector).unwrap_or_else(|| {
                    panic!("OS resources of syscall '{syscall_selector:?}' are unknown.")
                });
            os_additional_resources += &(syscall_resources * *count);
        }

        Ok(os_additional_resources)
    }

    fn resources_params_for_tx_type(&self, tx_type: &TransactionType) -> &ResourcesParams {
        &(self
            .execute_txs_inner
            .get(tx_type)
            .unwrap_or_else(|| panic!("should contain transaction type '{tx_type:?}'."))
            .deprecated_resources)
    }

    fn resources_for_tx_type(
        &self,
        tx_type: &TransactionType,
        calldata_length: usize,
    ) -> ExecutionResources {
        let resources_vector = self.resources_params_for_tx_type(tx_type);
        &resources_vector.constant + &(&(resources_vector.calldata_factor) * calldata_length)
    }

    fn os_kzg_da_resources(&self, data_segment_length: usize) -> ExecutionResources {
        &(&self.compute_os_kzg_commitment_info * data_segment_length)
            + &poseidon_hash_many_cost(data_segment_length)
    }
}

impl<'de> Deserialize<'de> for OsResources {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let os_resources = Self::deserialize(deserializer)?;

        // Validations.

        #[cfg(not(test))]
        os_resources.validate::<D>()?;

        Ok(os_resources)
    }
}

// List of all gas cost constants that *must* be present in the JSON file, all other consts are
// ignored. See documentation in core/os/constants.cairo.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GasCosts {
    pub step_gas_cost: u64,
    pub range_check_gas_cost: u64,
    pub memory_hole_gas_cost: u64,
    // An estimation of the initial gas for a transaction to run with. This solution is
    // temporary and this value will become a field of the transaction.
    pub initial_gas_cost: u64,
    // ** Compiler gas costs **
    pub entry_point_initial_budget: u64,
    // The initial gas budget for a system call (this value is hard-coded by the compiler).
    // This needs to be high enough to cover OS costs in the case of failure due to out of gas.
    pub syscall_base_gas_cost: u64,
    // ** OS gas costs **
    pub entry_point_gas_cost: u64,
    pub fee_transfer_gas_cost: u64,
    pub transaction_gas_cost: u64,
    // ** Required gas for each syscall **
    pub call_contract_gas_cost: u64,
    pub deploy_gas_cost: u64,
    pub get_block_hash_gas_cost: u64,
    pub get_execution_info_gas_cost: u64,
    pub library_call_gas_cost: u64,
    pub replace_class_gas_cost: u64,
    pub storage_read_gas_cost: u64,
    pub storage_write_gas_cost: u64,
    pub emit_event_gas_cost: u64,
    pub send_message_to_l1_gas_cost: u64,
    pub secp256k1_add_gas_cost: u64,
    pub secp256k1_get_point_from_x_gas_cost: u64,
    pub secp256k1_get_xy_gas_cost: u64,
    pub secp256k1_mul_gas_cost: u64,
    pub secp256k1_new_gas_cost: u64,
    pub secp256r1_add_gas_cost: u64,
    pub secp256r1_get_point_from_x_gas_cost: u64,
    pub secp256r1_get_xy_gas_cost: u64,
    pub secp256r1_mul_gas_cost: u64,
    pub secp256r1_new_gas_cost: u64,
    pub keccak_gas_cost: u64,
    pub keccak_round_cost_gas_cost: u64,
}

impl GasCosts {
    // List of additinal fields, beside the fields of GasCosts, that are not used by Blockifier but
    // included for transparency. These fields will be ignored during the creation of the GasCosts
    // object.
    const ADDITIONAL_FIELDS: [&'static str; 25] = [
        "block_hash_contract_address",
        "constructor_entry_point_selector",
        "default_entry_point_selector",
        "entry_point_type_constructor",
        "entry_point_type_external",
        "entry_point_type_l1_handler",
        "error_block_number_out_of_range",
        "error_invalid_input_len",
        "error_invalid_argument",
        "error_out_of_gas",
        "execute_entry_point_selector",
        "l1_gas",
        "l1_gas_index",
        "l1_handler_version",
        "l2_gas",
        "l2_gas_index",
        "nop_entry_point_offset",
        "sierra_array_len_bound",
        "stored_block_hash_buffer",
        "transfer_entry_point_selector",
        "validate_declare_entry_point_selector",
        "validate_deploy_entry_point_selector",
        "validate_entry_point_selector",
        "validate_rounding_consts",
        "validated",
    ];
}

// Below, serde first deserializes the json into a regular IndexMap wrapped by the newtype
// `OsConstantsRawJson`, then calls the `try_from` of the newtype, which handles the
// conversion into actual values.
// TODO: consider encoding the * and + operations inside the json file, instead of hardcoded below
// in the `try_from`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(try_from = "OsConstantsRawJson")]
pub struct OSConstants {
    pub gas_costs: GasCosts,
    validate_rounding_consts: ValidateRoundingConsts,
}

impl OSConstants {
    #[cfg(test)]
    fn create_from_subset(
        subset_of_os_constants: &str,
    ) -> Result<OSConstants, VersionedConstantsError> {
        use crate::utils::update_json_value;

        let subset_of_os_constants: Value = serde_json::from_str(subset_of_os_constants)?;
        let mut os_constants: Value = serde_json::from_str::<Value>(DEFAULT_CONSTANTS_JSON)?
            .get("os_constants")
            .ok_or_else(|| VersionedConstantsError::MissingOSConstants)?
            .clone();
        update_json_value(&mut os_constants, subset_of_os_constants)?;
        let os_constants: OSConstants = serde_json::from_value(os_constants)?;
        Ok(os_constants)
    }
}

impl TryFrom<OsConstantsRawJson> for OSConstants {
    type Error = OsConstantsSerdeError;

    fn try_from(raw_json_data: OsConstantsRawJson) -> Result<Self, Self::Error> {
        // TODO(Ori, 15/03/2024): Move these two lines to an implementation of TryFrom for GasCosts.
        let gas_costs_map = raw_json_data.parse_gas_costs()?;
        let gas_costs: GasCosts =
            serde_json::to_value(&gas_costs_map).and_then(serde_json::from_value)?;
        let validate_rounding_consts = raw_json_data.validate_rounding_consts;
        let os_constants = OSConstants { gas_costs, validate_rounding_consts };

        Ok(os_constants)
    }
}

// Intermediate representation of the JSON file in order to make the deserialization easier, using a
// regular try_from.
#[derive(Debug, Deserialize)]
struct OsConstantsRawJson {
    #[serde(flatten)]
    raw_json_file_as_dict: IndexMap<String, Value>,
    #[serde(default)]
    validate_rounding_consts: ValidateRoundingConsts,
}

impl OsConstantsRawJson {
    fn parse_gas_costs(&self) -> Result<IndexMap<String, u64>, OsConstantsSerdeError> {
        let mut gas_costs = IndexMap::new();
        let additional_fields: IndexSet<_> = GasCosts::ADDITIONAL_FIELDS.iter().copied().collect();
        for (key, value) in &self.raw_json_file_as_dict {
            if additional_fields.contains(key.as_str()) {
                // Ignore additional consts.
                continue;
            }

            self.recursive_add_to_gas_costs(key, value, &mut gas_costs)?;
        }
        Ok(gas_costs)
    }

    /// Recursively adds a key to gas costs, calculating its value after processing any nested keys.
    // Invariant: there is no circular dependency between key definitions.
    fn recursive_add_to_gas_costs(
        &self,
        key: &str,
        value: &Value,
        gas_costs: &mut IndexMap<String, u64>,
    ) -> Result<(), OsConstantsSerdeError> {
        if gas_costs.contains_key(key) {
            return Ok(());
        }

        match value {
            Value::Number(n) => {
                let value = n.as_u64().ok_or_else(|| OsConstantsSerdeError::OutOfRange {
                    key: key.to_string(),
                    value: n.clone(),
                })?;
                gas_costs.insert(key.to_string(), value);
            }
            Value::Object(obj) => {
                // Converts:
                // `k_1: {k_2: factor_1, k_3: factor_2}`
                // into:
                // k_1 = k_2 * factor_1 + k_3 * factor_2
                let mut value = 0;
                for (inner_key, factor) in obj {
                    let inner_value =
                        &self.raw_json_file_as_dict.get(inner_key).ok_or_else(|| {
                            OsConstantsSerdeError::KeyNotFound {
                                key: key.to_string(),
                                inner_key: inner_key.clone(),
                            }
                        })?;
                    self.recursive_add_to_gas_costs(inner_key, inner_value, gas_costs)?;
                    let inner_key_value = gas_costs.get(inner_key).ok_or_else(|| {
                        OsConstantsSerdeError::KeyNotFound {
                            key: key.to_string(),
                            inner_key: inner_key.to_string(),
                        }
                    })?;
                    let factor =
                        factor.as_u64().ok_or_else(|| OsConstantsSerdeError::OutOfRangeFactor {
                            key: key.to_string(),
                            value: factor.clone(),
                        })?;
                    value += inner_key_value * factor;
                }
                gas_costs.insert(key.to_string(), value);
            }
            Value::String(_) => {
                panic!(
                    "String values should have been previously filtered out in the whitelist \
                     check and should not be depended on"
                )
            }
            _ => return Err(OsConstantsSerdeError::UnhandledValueType(value.clone())),
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VersionedConstantsError {
    #[error(transparent)]
    InvalidJSONValue(#[from] utils::UtilsError),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("VersionedConstants must include OSConstants")]
    MissingOSConstants,
    #[error("JSON file cannot be serialized into VersionedConstants: {0}")]
    ParseError(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum OsConstantsSerdeError {
    #[error("Value cannot be cast into u64: {0}")]
    InvalidFactorFormat(Value),
    #[error("Unknown key '{inner_key}' used to create value for '{key}'")]
    KeyNotFound { key: String, inner_key: String },
    #[error("Value {value} for key '{key}' is out of range and cannot be cast into u64")]
    OutOfRange { key: String, value: Number },
    #[error(
        "Value {value} used to create value for key '{key}' is out of range and cannot be cast \
         into u64"
    )]
    OutOfRangeFactor { key: String, value: Value },
    #[error("JSON file cannot be serialized into VersionedConstants: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("Unhandled value type: {0}")]
    UnhandledValueType(Value),
    #[error("Validation failed: {0}")]
    ValidationError(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "ResourceParamsRaw")]
pub struct ResourcesParams {
    pub constant: ExecutionResources,
    pub calldata_factor: ExecutionResources,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ResourceParamsRaw {
    #[serde(flatten)]
    raw_resource_params_as_dict: Map<String, Value>,
}

impl TryFrom<ResourceParamsRaw> for ResourcesParams {
    type Error = VersionedConstantsError;

    fn try_from(mut json_data: ResourceParamsRaw) -> Result<Self, Self::Error> {
        let constant_value = json_data.raw_resource_params_as_dict.remove("constant");
        let calldata_factor_value = json_data.raw_resource_params_as_dict.remove("calldata_factor");

        let (constant, calldata_factor) = match (constant_value, calldata_factor_value) {
            (Some(constant), Some(calldata_factor)) => (constant, calldata_factor),
            (Some(_), None) => {
                return Err(serde_json::Error::custom(
                    "Malformed JSON: If `constant` is present, then so should `calldata_factor`",
                ))?;
            }
            (None, _) => {
                // If `constant` is not found, use the entire map for `constant` and default
                // `calldata_factor`
                let entire_value = std::mem::take(&mut json_data.raw_resource_params_as_dict);
                (Value::Object(entire_value), serde_json::to_value(ExecutionResources::default())?)
            }
        };

        Ok(Self {
            constant: serde_json::from_value(constant)?,
            calldata_factor: serde_json::from_value(calldata_factor)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ValidateRoundingConsts {
    // Flooring factor for block number in validate mode.
    pub validate_block_number_rounding: u64,
    // Flooring factor for timestamp in validate mode.
    pub validate_timestamp_rounding: u64,
}

impl Default for ValidateRoundingConsts {
    fn default() -> Self {
        Self { validate_block_number_rounding: 1, validate_timestamp_rounding: 1 }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResourcesByVersion {
    pub resources: ResourcesParams,
    pub deprecated_resources: ResourcesParams,
}
