use std::collections::{HashMap, HashSet};

use cairo_felt::Felt252;
use itertools::concat;
use num_traits::Pow;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::data_availability::DataAvailabilityMode;
use starknet_api::transaction::{
    AccountDeploymentData, Fee, PaymasterData, Resource, ResourceBounds, ResourceBoundsMapping,
    Tip, TransactionHash, TransactionSignature, TransactionVersion,
};
use strum_macros::EnumIter;

use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::calculate_tx_fee;
use crate::transaction::constants;
use crate::transaction::errors::TransactionExecutionError;

pub type TransactionExecutionResult<T> = Result<T, TransactionExecutionError>;

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

#[derive(EnumIter, Eq, PartialEq)]
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

    pub fn max_fee(&self) -> Fee {
        match self {
            Self::Current(context) => {
                let l1_resource_bounds = context.l1_resource_bounds().unwrap_or_default();
                // TODO(nir, 01/11/2023): Change to max_amount * block_context.gas_price.
                Fee(l1_resource_bounds.max_amount as u128 * l1_resource_bounds.max_price_per_unit)
            }
            Self::Deprecated(context) => context.max_fee,
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

    pub fn enforce_fee(&self) -> bool {
        match self {
            AccountTransactionContext::Current(current_context) => {
                let l1_bounds = current_context
                    .l1_resource_bounds()
                    .expect("L1 resource bounds should be set.");
                l1_bounds.max_amount as u128 * l1_bounds.max_price_per_unit > 0
            }
            AccountTransactionContext::Deprecated(deprecated_context) => {
                deprecated_context.max_fee != Fee(0)
            }
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
    pub fn l1_resource_bounds(&self) -> Option<ResourceBounds> {
        self.resource_bounds.0.get(&Resource::L1Gas).copied()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeprecatedAccountTransactionContext {
    pub common_fields: CommonAccountFields,
    pub max_fee: Fee,
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
    pub fn non_optional_call_infos(&self) -> Vec<&CallInfo> {
        let call_infos = vec![
            self.validate_call_info.as_ref(),
            self.execute_call_info.as_ref(),
            self.fee_transfer_call_info.as_ref(),
        ];

        call_infos.into_iter().flatten().collect()
    }

    /// Returns the set of class hashes that were executed during this transaction execution.
    pub fn get_executed_class_hashes(&self) -> HashSet<ClassHash> {
        concat(
            self.non_optional_call_infos()
                .into_iter()
                .map(|call_info| call_info.get_executed_class_hashes()),
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
        calculate_tx_fee(resources, block_context, &self.fee_type())
    }
}
