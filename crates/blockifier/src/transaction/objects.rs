use std::collections::{HashMap, HashSet};

use itertools::concat;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::transaction::{Fee, TransactionHash, TransactionSignature, TransactionVersion};
use strum_macros::EnumIter;

use crate::block_context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::fee::fee_utils::calculate_tx_fee;
use crate::transaction::errors::TransactionExecutionError;

pub type TransactionExecutionResult<T> = Result<T, TransactionExecutionError>;

macro_rules! add_getters {
    ($(($field:ident, $field_type:ty)),*) => {
        $(pub fn $field(&self) -> $field_type {
            match self{
                Self::Deprecated(context) => context.$field,
            }
        })*
    };
}

#[derive(EnumIter)]
pub enum FeeType {
    Strk,
    Eth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountTransactionContext {
    Deprecated(DeprecatedAccountTransactionContext),
}

impl AccountTransactionContext {
    add_getters!(
        (transaction_hash, TransactionHash),
        (version, TransactionVersion),
        (nonce, Nonce),
        (sender_address, ContractAddress)
    );

    pub fn signature(&self) -> TransactionSignature {
        match self {
            Self::Deprecated(context) => context.signature.clone(),
        }
    }

    pub fn max_fee(&self) -> Fee {
        match self {
            Self::Deprecated(context) => context.max_fee,
        }
    }

    pub fn is_v0(&self) -> bool {
        self.version() == TransactionVersion::ZERO
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

/// Contains the account information of the transaction (outermost call).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeprecatedAccountTransactionContext {
    pub transaction_hash: TransactionHash,
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: TransactionSignature,
    pub nonce: Nonce,
    pub sender_address: ContractAddress,
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
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ResourcesMapping(pub HashMap<String, usize>);

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
