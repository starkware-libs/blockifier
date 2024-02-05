use std::collections::{HashMap, HashSet};

use itertools::concat;
use num_traits::Pow;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, Fee, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping,
    Tip, TransactionHash, TransactionSignature, TransactionVersion,
};
use starknet_types_core::felt::Felt;
use strum_macros::EnumIter;

use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::state::cached_state::StorageEntry;
use crate::transaction::constants;
use crate::transaction::errors::{
    TransactionExecutionError, TransactionFeeError, TransactionPreValidationError,
};

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

#[derive(Clone, Copy, Hash, EnumIter, Eq, PartialEq)]
pub enum FeeType {
    Strk,
    Eth,
}

/// Contains the account information of the transaction (outermost call).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountTransactionContext {
    Current(CurrentAccountTransactionContext),
    Deprecated(DeprecatedAccountTransactionContext),
}

impl AccountTransactionContext {
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

        let query_version_base = Pow::pow(Felt::TWO, constants::QUERY_VERSION_BASE_BIT);
        let query_version = query_version_base + version.0;
        TransactionVersion(query_version)
    }

    pub fn enforce_fee(&self) -> TransactionFeeResult<bool> {
        match self {
            AccountTransactionContext::Current(context) => {
                let l1_bounds = context.l1_resource_bounds()?;
                let max_amount: u128 = l1_bounds.max_amount.into();
                Ok(max_amount * l1_bounds.max_price_per_unit > 0)
            }
            AccountTransactionContext::Deprecated(context) => Ok(context.max_fee != Fee(0)),
        }
    }
}

impl HasRelatedFeeType for AccountTransactionContext {
    fn version(&self) -> TransactionVersion {
        self.version()
    }

    fn is_l1_handler(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentAccountTransactionContext {
    pub common_fields: CommonAccountFields,
    pub resource_bounds: ResourceBoundsMapping,
    pub tip: Tip,
    pub nonce_data_availability_mode: DataAvailabilityMode,
    pub fee_data_availability_mode: DataAvailabilityMode,
    pub paymaster_data: PaymasterData,
    pub account_deployment_data: AccountDeploymentData,
}

impl CurrentAccountTransactionContext {
    /// Fetch the L1 resource bounds, if they exist.
    pub fn l1_resource_bounds(&self) -> TransactionFeeResult<ResourceBounds> {
        match self.resource_bounds.0.get(&Resource::L1Gas).copied() {
            Some(bounds) => Ok(bounds),
            None => Err(TransactionFeeError::MissingL1GasBounds),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeprecatedAccountTransactionContext {
    pub common_fields: CommonAccountFields,
    pub max_fee: Fee,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GasAndBlobGasUsages {
    pub gas_usage: u128,
    pub blob_gas_usage: u128,
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
#[derive(Debug, Default, Eq, PartialEq)]
pub struct TransactionExecutionInfo {
    /// Transaction validation call info; [None] for `L1Handler`.
    pub validate_call_info: Option<CallInfo>,
    /// Transaction execution call info; [None] for `Declare`.
    pub execute_call_info: Option<CallInfo>,
    /// Fee transfer call info; [None] for `L1Handler`.
    pub fee_transfer_call_info: Option<CallInfo>,
    /// The actual fee that was charged (in Wei).
    pub actual_fee: Fee,
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

    pub fn is_reverted(&self) -> bool {
        self.revert_error.is_some()
    }
}

/// A mapping from a transaction execution resource to its actual usage.
#[cfg_attr(test, derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ResourcesMapping(pub HashMap<String, usize>);

impl ResourcesMapping {
    #[cfg(test)]
    pub fn n_steps(&self) -> usize {
        *self.0.get(crate::abi::constants::N_STEPS_RESOURCE).unwrap()
    }

    #[cfg(test)]
    pub fn gas_usage(&self) -> usize {
        *self.0.get(crate::abi::constants::GAS_USAGE).unwrap()
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
