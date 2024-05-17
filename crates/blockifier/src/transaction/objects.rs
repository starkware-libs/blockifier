use std::collections::HashMap;

use cairo_felt::Felt252;
use cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::Pow;
use serde::Serialize;
use starknet_api::core::{ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, Fee, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping,
    Tip, TransactionHash, TransactionSignature, TransactionVersion,
};
use strum_macros::EnumIter;

use crate::abi::constants as abi_constants;
use crate::context::BlockContext;
use crate::execution::call_info::{CallInfo, ExecutionSummary, MessageL1CostInfo, OrderedEvent};
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::eth_gas_constants;
use crate::fee::fee_utils::{calculate_l1_gas_by_vm_usage, calculate_tx_fee};
use crate::fee::gas_usage::{
    get_consumed_message_to_l2_emissions_cost, get_da_gas_cost,
    get_log_message_to_l1_emissions_cost, get_onchain_data_segment_length,
};
use crate::state::cached_state::StateChangesCount;
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::utils::{u128_from_usize, usize_from_u128};
use crate::versioned_constants::VersionedConstants;

#[cfg(test)]
#[path = "objects_test.rs"]
pub mod objects_test;

pub type TransactionExecutionResult<T> = Result<T, TransactionExecutionError>;
pub type TransactionFeeResult<T> = Result<T, TransactionFeeError>;
pub type TransactionPreValidationResult<T> = Result<T, TransactionPreValidationError>;

macro_rules! implement_getters {
    ($(($field:ident, $field_type:ty)),*) => {
        $(pub fn $field(&self) -> $field_type {
            match self{
                Self::Current(context) => context.common_fields.$field,
                Self::Deprecated(context) => context.common_fields.$field,
            }
        })*
    };
}

/// Contains the account information of the transaction (outermost call).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionInfo {
    Current(CurrentTransactionInfo),
    Deprecated(DeprecatedTransactionInfo),
}

impl TransactionInfo {
    implement_getters!(
        (transaction_hash, TransactionHash),
        (version, TransactionVersion),
        (nonce, Nonce),
        (sender_address, ContractAddress),
        (only_query, bool)
    );

    pub fn signature(&self) -> TransactionSignature {
        match self {
            Self::Current(context) => context.common_fields.signature.clone(),
            Self::Deprecated(context) => context.common_fields.signature.clone(),
        }
    }

    pub fn is_v0(&self) -> bool {
        self.version() == TransactionVersion::ZERO
    }

    pub fn signed_version(&self) -> TransactionVersion {
        let version = self.version();
        if !self.only_query() {
            return version;
        }

        let query_version_base = Pow::pow(Felt252::from(2_u8), constants::QUERY_VERSION_BASE_BIT);
        let query_version = query_version_base + stark_felt_to_felt(version.0);
        TransactionVersion(felt_to_stark_felt(&query_version))
    }

    pub fn enforce_fee(&self) -> TransactionFeeResult<bool> {
        match self {
            TransactionInfo::Current(context) => {
                let l1_bounds = context.l1_resource_bounds()?;
                let max_amount: u128 = l1_bounds.max_amount.into();
                Ok(max_amount * l1_bounds.max_price_per_unit > 0)
            }
            TransactionInfo::Deprecated(context) => Ok(context.max_fee != Fee(0)),
        }
    }

    pub fn max_fee(&self) -> TransactionFeeResult<Fee> {
        match self {
            Self::Current(context) => {
                let l1_bounds = context.l1_resource_bounds()?;
                Ok(Fee(u128::from(l1_bounds.max_amount) * l1_bounds.max_price_per_unit))
            }
            Self::Deprecated(context) => Ok(context.max_fee),
        }
    }
}

impl HasRelatedFeeType for TransactionInfo {
    fn version(&self) -> TransactionVersion {
        self.version()
    }

    fn is_l1_handler(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentTransactionInfo {
    pub common_fields: CommonAccountFields,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub account_deployment_data: AccountDeploymentData,
}

impl Default for CurrentTransactionInfo {
    fn default() -> Self {
        Self {
            common_fields: Default::default(),
            resource_bounds: Default::default(),
            tip: Default::default(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            paymaster_data: Default::default(),
            account_deployment_data: Default::default(),
        }
    }
}

impl CurrentTransactionInfo {
    /// Fetch the L1 resource bounds, if they exist.
    pub fn l1_resource_bounds(&self) -> TransactionFeeResult<ResourceBounds> {
        match self.resource_bounds.0.get(&Resource::L1Gas).copied() {
            Some(bounds) => Ok(bounds),
            None => Err(TransactionFeeError::MissingL1GasBounds),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeprecatedTransactionInfo {
    pub common_fields: CommonAccountFields,
    pub max_fee: Fee,
}

#[derive(
    derive_more::Add, derive_more::Sum, Clone, Copy, Debug, Default, Eq, PartialEq, Serialize,
)]
pub struct GasVector {
    pub l1_gas: u128,
    pub l1_data_gas: u128,
}

impl GasVector {
    pub fn from_l1_gas(l1_gas: u128) -> Self {
        Self { l1_gas, l1_data_gas: 0 }
    }

    pub fn from_l1_data_gas(l1_data_gas: u128) -> Self {
        Self { l1_gas: 0, l1_data_gas }
    }

    /// Computes the cost (in fee token units) of the gas vector (saturating on overflow).
    pub fn saturated_cost(&self, gas_price: u128, blob_gas_price: u128) -> Fee {
        let l1_gas_cost = self.l1_gas.checked_mul(gas_price).unwrap_or_else(|| {
            log::warn!(
                "L1 gas cost overflowed: multiplication of {} by {} resulted in overflow.",
                self.l1_gas,
                gas_price
            );
            u128::MAX
        });
        let l1_data_gas_cost = self.l1_data_gas.checked_mul(blob_gas_price).unwrap_or_else(|| {
            log::warn!(
                "L1 blob gas cost overflowed: multiplication of {} by {} resulted in overflow.",
                self.l1_data_gas,
                blob_gas_price
            );
            u128::MAX
        });
        let total = l1_gas_cost.checked_add(l1_data_gas_cost).unwrap_or_else(|| {
            log::warn!(
                "Total gas cost overflowed: addition of {} and {} resulted in overflow.",
                l1_gas_cost,
                l1_data_gas_cost
            );
            u128::MAX
        });
        Fee(total)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommonAccountFields {
    pub transaction_hash: TransactionHash,
    pub version: TransactionVersion,
    pub signature: TransactionSignature,
    pub nonce: Nonce,
    pub sender_address: ContractAddress,
    pub only_query: bool,
}

/// Contains the information gathered by the execution of a transaction.
#[derive(Debug, Default, PartialEq)]
pub struct TransactionExecutionInfo {
    /// Transaction validation call info; [None] for `L1Handler`.
    pub validate_call_info: Option<CallInfo>,
    /// Transaction execution call info; [None] for `Declare`.
    pub execute_call_info: Option<CallInfo>,
    /// Fee transfer call info; [None] for `L1Handler`.
    pub fee_transfer_call_info: Option<CallInfo>,
    /// The actual fee that was charged (in Wei).
    pub actual_fee: Fee,
    /// Actual gas consumption the transaction is charged for data availability.
    pub da_gas: GasVector,
    /// Actual execution resources the transaction is charged for,
    /// including L1 gas and additional OS resources estimation.
    pub actual_resources: TransactionResources,
    /// Error string for reverted transactions; [None] if transaction execution was successful.
    // TODO(Dori, 1/8/2023): If the `Eq` and `PartialEq` traits are removed, or implemented on all
    //   internal structs in this enum, this field should be `Option<TransactionExecutionError>`.
    pub revert_error: Option<String>,
}

impl TransactionExecutionInfo {
    pub fn non_optional_call_infos(&self) -> impl Iterator<Item = &CallInfo> {
        self.validate_call_info
            .iter()
            .chain(self.execute_call_info.iter())
            .chain(self.fee_transfer_call_info.iter())
    }

    pub fn is_reverted(&self) -> bool {
        self.revert_error.is_some()
    }

    /// Returns a summary of transaction execution, including executed class hashes, visited storage
    /// entries, L2-to-L1_payload_lengths, and the number of emitted events.
    pub fn summarize(&self) -> ExecutionSummary {
        self.non_optional_call_infos().map(|call_info| call_info.summarize()).sum()
    }
}

/// A mapping from a transaction execution resource to its actual usage.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ResourcesMapping(pub HashMap<String, usize>);

impl ResourcesMapping {
    #[cfg(test)]
    pub fn n_steps(&self) -> usize {
        *self.0.get(abi_constants::N_STEPS_RESOURCE).unwrap()
    }

    #[cfg(test)]
    pub fn gas_usage(&self) -> usize {
        *self.0.get(abi_constants::L1_GAS_USAGE).unwrap()
    }

    #[cfg(test)]
    pub fn blob_gas_usage(&self) -> usize {
        *self.0.get(abi_constants::BLOB_GAS_USAGE).unwrap()
    }
}

/// Containes all the L2 resources consumed by a transaction
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StarknetResources {
    pub calldata_length: usize,
    pub state_changes_for_fee: StateChangesCount,
    pub message_cost_info: MessageL1CostInfo,
    pub l1_handler_payload_size: Option<usize>,
    pub n_events: usize,
    signature_length: usize,
    code_size: usize,
    total_event_keys: u128,
    total_event_data_size: u128,
}

impl StarknetResources {
    pub fn new<'a>(
        calldata_length: usize,
        signature_length: usize,
        code_size: usize,
        state_changes_count: StateChangesCount,
        l1_handler_payload_size: Option<usize>,
        call_infos: impl Iterator<Item = &'a CallInfo> + Clone,
    ) -> Self {
        let (n_events, total_event_keys, total_event_data_size) =
            StarknetResources::calculate_events_resources(call_infos.clone());

        Self {
            calldata_length,
            signature_length,
            code_size,
            state_changes_for_fee: state_changes_count,
            l1_handler_payload_size,
            message_cost_info: MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size),
            n_events,
            total_event_keys,
            total_event_data_size,
        }
    }

    /// Returns the gas cost of the starknet resources, summing all components.
    pub fn to_gas_vector(
        &self,
        versioned_constants: &VersionedConstants,
        use_kzg_da: bool,
    ) -> GasVector {
        self.get_calldata_and_signature_cost(versioned_constants)
            + self.get_code_cost(versioned_constants)
            + self.get_state_changes_cost(use_kzg_da)
            + self.get_messages_cost()
            + self.get_events_cost(versioned_constants)
    }

    // Returns the gas cost for transaction calldata and transaction signature. Each felt costs a
    // fixed and configurable amount of gas. This cost represents the cost of storing the
    // calldata and the signature on L2.
    pub fn get_calldata_and_signature_cost(
        &self,
        versioned_constants: &VersionedConstants,
    ) -> GasVector {
        // TODO(Avi, 20/2/2024): Calculate the number of bytes instead of the number of felts.
        let total_data_size = u128_from_usize(self.calldata_length + self.signature_length);
        let l1_gas = (versioned_constants.l2_resource_gas_costs.gas_per_data_felt
            * total_data_size)
            .to_integer();
        GasVector::from_l1_gas(l1_gas)
    }

    /// Returns an estimation of the gas usage for processing L1<>L2 messages on L1. Accounts for
    /// Starknet contract only.
    fn get_messages_gas_usage(&self) -> GasVector {
        let n_l2_to_l1_messages = self.message_cost_info.l2_to_l1_payload_lengths.len();
        let n_l1_to_l2_messages = usize::from(self.l1_handler_payload_size.is_some());

        GasVector::from_l1_gas(
            // Starknet's updateState gets the message segment as an argument.
            u128_from_usize(
                self.message_cost_info.message_segment_length * eth_gas_constants::GAS_PER_MEMORY_WORD
                // Starknet's updateState increases a (storage) counter for each L2-to-L1 message.
                + n_l2_to_l1_messages * eth_gas_constants::GAS_PER_ZERO_TO_NONZERO_STORAGE_SET
                // Starknet's updateState decreases a (storage) counter for each L1-to-L2 consumed
                // message (note that we will probably get a refund of 15,000 gas for each consumed
                // message but we ignore it since refunded gas cannot be used for the current
                // transaction execution).
                + n_l1_to_l2_messages * eth_gas_constants::GAS_PER_COUNTER_DECREASE,
            ),
        ) + get_consumed_message_to_l2_emissions_cost(self.l1_handler_payload_size)
            + get_log_message_to_l1_emissions_cost(&self.message_cost_info.l2_to_l1_payload_lengths)
    }

    /// Returns an estimation of the gas usage for processing L1<>L2 messages on L1. Accounts for
    /// both Starknet and SHARP contracts.
    pub fn get_messages_cost(&self) -> GasVector {
        let starknet_gas_usage = self.get_messages_gas_usage();
        let sharp_gas_usage = GasVector::from_l1_gas(u128_from_usize(
            self.message_cost_info.message_segment_length
                * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD,
        ));

        starknet_gas_usage + sharp_gas_usage
    }

    /// Calculates the L1 resources used by L1<>L2 messages.
    /// Returns the total message segment length and the gas weight.
    pub fn calculate_message_l1_resources(&self) -> (usize, usize) {
        let message_segment_length = self.message_cost_info.message_segment_length;
        let gas_usage = self.get_messages_gas_usage();
        // TODO(Avi, 30/03/2024): Consider removing "l1_gas_usage" from actual resources.
        let gas_weight = usize_from_u128(gas_usage.l1_gas)
            .expect("This conversion should not fail as the value is a converted usize.");
        (message_segment_length, gas_weight)
    }

    /// Returns the gas cost of declared class codes.
    pub fn get_code_cost(&self, versioned_constants: &VersionedConstants) -> GasVector {
        GasVector::from_l1_gas(
            (versioned_constants.l2_resource_gas_costs.gas_per_code_byte
                * u128_from_usize(self.code_size))
            .to_integer(),
        )
    }

    /// Returns the gas cost of the transaction's state changes.
    pub fn get_state_changes_cost(&self, use_kzg_da: bool) -> GasVector {
        // TODO(Nimrod, 29/3/2024): delete `get_da_gas_cost` and move it's logic here.
        get_da_gas_cost(&self.state_changes_for_fee, use_kzg_da)
    }

    /// Returns the gas cost of the transaction's emmited events.
    pub fn get_events_cost(&self, versioned_constants: &VersionedConstants) -> GasVector {
        let l2_resource_gas_costs = &versioned_constants.l2_resource_gas_costs;
        let (event_key_factor, data_word_cost) =
            (l2_resource_gas_costs.event_key_factor, l2_resource_gas_costs.gas_per_data_felt);
        let l1_gas: u128 = (data_word_cost
            * (event_key_factor * self.total_event_keys + self.total_event_data_size))
            .to_integer();

        GasVector::from_l1_gas(l1_gas)
    }

    pub fn get_onchain_data_segment_length(&self) -> usize {
        get_onchain_data_segment_length(&self.state_changes_for_fee)
    }

    /// Private and static method that calculates the n_events, total_event_keys and
    /// total_event_data_size fields according to the call_infos of a transaction.
    fn calculate_events_resources<'a>(
        call_infos: impl Iterator<Item = &'a CallInfo> + Clone,
    ) -> (usize, u128, u128) {
        let mut total_event_keys = 0;
        let mut total_event_data_size = 0;
        let mut n_events = 0;
        for call_info in call_infos.clone() {
            for inner_call in call_info.iter() {
                for OrderedEvent { event, .. } in inner_call.execution.events.iter() {
                    // TODO(barak: 18/03/2024): Once we start charging per byte
                    // change to num_bytes_keys
                    // and num_bytes_data.
                    total_event_data_size += u128_from_usize(event.data.0.len());
                    total_event_keys += u128_from_usize(event.keys.len());
                }
                n_events += inner_call.execution.events.len();
            }
        }
        (n_events, total_event_keys, total_event_data_size)
    }
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct TransactionResources {
    pub starknet_resources: StarknetResources,
    pub vm_resources: ExecutionResources,
    pub n_reverted_steps: usize,
}

impl TransactionResources {
    /// Computes and returns the total L1 gas consumption.
    /// We add the l1_gas_usage (which may include, for example, the direct cost of L2-to-L1
    /// messages) to the gas consumed by Cairo VM resource.
    pub fn to_gas_vector(
        &self,
        versioned_constants: &VersionedConstants,
        use_kzg_da: bool,
    ) -> TransactionFeeResult<GasVector> {
        Ok(self.starknet_resources.to_gas_vector(versioned_constants, use_kzg_da)
            + calculate_l1_gas_by_vm_usage(
                versioned_constants,
                &self.vm_resources,
                self.n_reverted_steps,
            )?)
    }

    pub fn to_resources_mapping(
        &self,
        versioned_constants: &VersionedConstants,
        use_kzg_da: bool,
        with_reverted_steps: bool,
    ) -> ResourcesMapping {
        let GasVector { l1_gas, l1_data_gas } =
            self.starknet_resources.to_gas_vector(versioned_constants, use_kzg_da);
        let mut resources = self.vm_resources.to_resources_mapping();
        resources.0.extend(HashMap::from([
            (
                abi_constants::L1_GAS_USAGE.to_string(),
                usize_from_u128(l1_gas)
                    .expect("This conversion should not fail as the value is a converted usize."),
            ),
            (
                abi_constants::BLOB_GAS_USAGE.to_string(),
                usize_from_u128(l1_data_gas)
                    .expect("This conversion should not fail as the value is a converted usize."),
            ),
        ]));
        let revrted_steps_to_add = if with_reverted_steps { self.n_reverted_steps } else { 0 };
        *resources.0.get_mut(abi_constants::N_STEPS_RESOURCE).unwrap_or(&mut 0) +=
            revrted_steps_to_add;
        resources
    }

    pub fn total_charged_steps(&self) -> usize {
        self.n_reverted_steps + self.vm_resources.n_steps
    }
}

pub trait ExecutionResourcesTraits {
    fn total_n_steps(&self) -> usize;
    fn to_resources_mapping(&self) -> ResourcesMapping;
    fn prover_builtins(&self) -> HashMap<String, usize>;
}

impl ExecutionResourcesTraits for ExecutionResources {
    fn total_n_steps(&self) -> usize {
        self.n_steps
            // Memory holes are slightly cheaper than actual steps, but we count them as such
            // for simplicity.
            + self.n_memory_holes
            // The "segment arena" builtin is not part of the prover (not in any proof layout);
            // It is transformed into regular steps by the OS program - each instance requires
            // approximately 10 steps.
            + abi_constants::N_STEPS_PER_SEGMENT_ARENA_BUILTIN
                * self
                    .builtin_instance_counter
                    .get(SEGMENT_ARENA_BUILTIN_NAME)
                    .cloned()
                    .unwrap_or_default()
    }

    fn prover_builtins(&self) -> HashMap<String, usize> {
        let mut builtins = self.builtin_instance_counter.clone();

        // See "total_n_steps" documentation.
        builtins.remove(SEGMENT_ARENA_BUILTIN_NAME);
        builtins
    }

    // TODO(Nimrod, 1/5/2024): Delete this function when it's no longer in use.
    fn to_resources_mapping(&self) -> ResourcesMapping {
        let mut map =
            HashMap::from([(abi_constants::N_STEPS_RESOURCE.to_string(), self.total_n_steps())]);
        map.extend(self.prover_builtins());

        ResourcesMapping(map)
    }
}

pub trait HasRelatedFeeType {
    fn version(&self) -> TransactionVersion;

    fn is_l1_handler(&self) -> bool;

    fn fee_type(&self) -> FeeType {
        if self.is_l1_handler() || self.version() < TransactionVersion::THREE {
            FeeType::Eth
        } else {
            FeeType::Strk
        }
    }

    fn calculate_tx_fee(
        &self,
        tx_resources: &TransactionResources,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<Fee> {
        Ok(calculate_tx_fee(tx_resources, block_context, &self.fee_type())?)
    }
}

#[derive(Clone, Copy, Hash, EnumIter, Eq, PartialEq)]
pub enum FeeType {
    Strk,
    Eth,
}

pub trait TransactionInfoCreator {
    fn create_tx_info(&self) -> TransactionInfo;
}
