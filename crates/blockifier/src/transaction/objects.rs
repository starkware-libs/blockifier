use std::collections::HashMap;

use cairo_felt::Felt252;
use num_traits::Pow;
use serde::Serialize;
use starknet_api::core::{ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, Fee, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping,
    Tip, TransactionHash, TransactionSignature, TransactionVersion,
};
use strum_macros::EnumIter;

use crate::context::BlockContext;
use crate::execution::call_info::{CallInfo, ExecutionSummary, MessageL1CostInfo};
use crate::execution::contract_class::ClassInfo;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::eth_gas_constants;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::fee::gas_usage::{get_da_gas_cost, get_messages_gas_usage};
use crate::state::cached_state::StateChangesCount;
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};
use crate::utils::u128_from_usize;
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
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
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
    pub actual_resources: ResourcesMapping,
    /// Error string for reverted transactions; [None] if transaction execution was successful.
    // TODO(Dori, 1/8/2023): If the `Eq` and `PartialEq` traits are removed, or implemented on all
    //   internal structs in this enum, this field should be `Option<TransactionExecutionError>`.
    pub revert_error: Option<String>,
    /// If not None, contains the resources to account for in the bouncer.
    pub bouncer_resources: ResourcesMapping,
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
    /// entries, and the number of emitted events.
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
        *self.0.get(crate::abi::constants::N_STEPS_RESOURCE).unwrap()
    }

    #[cfg(test)]
    pub fn gas_usage(&self) -> usize {
        *self.0.get(crate::abi::constants::L1_GAS_USAGE).unwrap()
    }

    #[cfg(test)]
    pub fn blob_gas_usage(&self) -> usize {
        *self.0.get(crate::abi::constants::BLOB_GAS_USAGE).unwrap()
    }
}

/// Containes all the L2 resources consumed by a transaction
#[derive(Clone, Debug, Default)]
pub struct StarknetResources {
    pub calldata_length: usize,
    pub state_changes_count: StateChangesCount,
    pub l1_handler_payload_size: Option<usize>,
    pub l2_to_l1_payload_lengths: Vec<usize>,
    signature_length: usize,
    code_size: usize,
    message_segment_length: usize,
}

impl StarknetResources {
    pub fn new<'a>(
        calldata_length: usize,
        signature_length: usize,
        class_info: Option<&ClassInfo>,
        state_changes_count: StateChangesCount,
        l1_handler_payload_size: Option<usize>,
        call_infos: impl Iterator<Item = &'a CallInfo>,
    ) -> Self {
        let (l2_to_l1_payload_lengths, message_segment_length) =
            StarknetResources::calculate_messages_resources(call_infos, l1_handler_payload_size)
                .unwrap();
        Self {
            calldata_length,
            signature_length,
            code_size: StarknetResources::calculate_code_size(class_info),
            state_changes_count,
            l1_handler_payload_size,
            l2_to_l1_payload_lengths,
            message_segment_length,
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
    }

    /// Sets the code_size field from a ClassInfo from (Sierra, Casm and ABI). Each code felt costs
    /// a fixed and configurable amount of gas. The cost is 0 for non-Declare transactions.
    pub fn set_code_size(&mut self, class_info: Option<&ClassInfo>) {
        self.code_size = StarknetResources::calculate_code_size(class_info);
    }

    /// Sets the l2_to_l1_payload_lengths, message_segment_length fields according to the call_infos
    /// of a transaction.
    pub fn set_message_resources<'a>(
        &mut self,
        call_infos: impl Iterator<Item = &'a CallInfo>,
    ) -> TransactionExecutionResult<()> {
        let (l2_to_l1_payload_lengths, message_segment_length) =
            StarknetResources::calculate_messages_resources(
                call_infos,
                self.l1_handler_payload_size,
            )?;
        self.message_segment_length = message_segment_length;
        self.l2_to_l1_payload_lengths = l2_to_l1_payload_lengths;
        Ok(())
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
    /// both Starknet and SHARP contracts.
    pub fn get_messages_cost(&self) -> GasVector {
        let starknet_gas_usage = get_messages_gas_usage(
            self.message_segment_length,
            &self.l2_to_l1_payload_lengths,
            self.l1_handler_payload_size,
        );
        let sharp_gas_usage = GasVector {
            l1_gas: u128_from_usize(
                self.message_segment_length * eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD,
            ),
            l1_data_gas: 0,
        };

        starknet_gas_usage + sharp_gas_usage
    }

    // Returns the gas cost of declared class codes.
    pub fn get_code_cost(&self, versioned_constants: &VersionedConstants) -> GasVector {
        GasVector::from_l1_gas(
            (versioned_constants.l2_resource_gas_costs.gas_per_code_byte
                * u128_from_usize(self.code_size))
            .to_integer(),
        )
    }

    // Returns the gas cost of the transaction's state changes.
    pub fn get_state_changes_cost(&self, use_kzg_da: bool) -> GasVector {
        // TODO(Nimrod, 29/3/2024): delete `get_da_gas_cost` and move it's logic here.
        get_da_gas_cost(&self.state_changes_count, use_kzg_da)
    }

    // Private and static method that calculates the code size from ClassInfo
    fn calculate_code_size(class_info: Option<&ClassInfo>) -> usize {
        if let Some(class_info) = class_info {
            (class_info.bytecode_length()
                + class_info.sierra_program_length())
                    // We assume each felt is a word.
                    * eth_gas_constants::WORD_WIDTH
                + class_info.abi_length()
        } else {
            0
        }
    }

    /// Private and static that calculates the l2_to_l1_payload_lengths, message_segment_length
    /// fields

    fn calculate_messages_resources<'a>(
        call_infos: impl Iterator<Item = &'a CallInfo>,
        l1_handler_payload_size: Option<usize>,
    ) -> TransactionExecutionResult<(Vec<usize>, usize)> {
        let MessageL1CostInfo { l2_to_l1_payload_lengths, message_segment_length } =
            MessageL1CostInfo::calculate(call_infos, l1_handler_payload_size)?;
        Ok((l2_to_l1_payload_lengths, message_segment_length))
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
        resources: &ResourcesMapping,
        block_context: &BlockContext,
    ) -> TransactionExecutionResult<Fee> {
        Ok(calculate_tx_fee(resources, block_context, &self.fee_type())?)
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
