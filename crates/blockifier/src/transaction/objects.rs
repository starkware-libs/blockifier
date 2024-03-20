use std::collections::{HashMap, HashSet};

use cairo_felt::Felt252;
use itertools::concat;
use num_traits::Pow;
use serde::Serialize;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, Fee, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping,
    Tip, TransactionHash, TransactionSignature, TransactionVersion,
};
use strum_macros::EnumIter;

use crate::context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::calculate_tx_fee;
use crate::state::cached_state::StorageEntry;
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};

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
            TransactionInfo::Current(context) => {
                let l1_bounds = context.l1_resource_bounds()?;
                Ok(Fee(l1_bounds.max_amount as u128 * l1_bounds.max_price_per_unit))
            }
            TransactionInfo::Deprecated(context) => Ok(context.max_fee),
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
}

impl TransactionExecutionInfo {
    pub fn non_optional_call_infos(&self) -> impl Iterator<Item = &CallInfo> {
        self.validate_call_info
            .iter()
            .chain(self.execute_call_info.iter())
            .chain(self.fee_transfer_call_info.iter())
    }

    /// Returns the set of class hashes that were executed during this transaction execution.
    pub fn get_executed_class_hashes(&self) -> HashSet<ClassHash> {
        concat(
            self.non_optional_call_infos().map(|call_info| call_info.get_executed_class_hashes()),
        )
    }

    /// Returns the set of storage entries visited during this transaction execution.
    pub fn get_visited_storage_entries(&self) -> HashSet<StorageEntry> {
        concat(
            self.non_optional_call_infos().map(|call_info| call_info.get_visited_storage_entries()),
        )
    }

    /// Returns the number of events emitted in this transaction execution.
    pub fn get_number_of_events(&self) -> usize {
        self.non_optional_call_infos().map(|call_info| call_info.get_number_of_events()).sum()
    }

    pub fn is_reverted(&self) -> bool {
        self.revert_error.is_some()
    }
}

/// A mapping from a transaction execution resource to its actual usage.
#[cfg_attr(test, derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
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
