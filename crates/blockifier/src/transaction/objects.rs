use std::collections::HashMap;

use starknet_api::core::{ContractAddress, Nonce};
use starknet_api::transaction::{Fee, TransactionHash, TransactionSignature, TransactionVersion};

use crate::execution::entry_point::CallInfo;
use crate::transaction::errors::TransactionExecutionError;

pub type TransactionExecutionResult<T> = Result<T, TransactionExecutionError>;

/// Contains the account information of the transaction (outermost call).
#[derive(Debug, Default, Eq, PartialEq)]
pub struct AccountTransactionContext {
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
    /// Transaction validation call info.
    pub validate_call_info: CallInfo,
    /// Transaction execution call info; trivial for `Declare`.
    pub execute_call_info: Option<CallInfo>,
    /// Fee transfer call info.
    pub fee_transfer_call_info: CallInfo,
    /// The actual fee that was charged (in Wei).
    pub actual_fee: Fee,
    /// Actual execution resources the transaction is charged for,
    /// including L1 gas and additional OS resources estimation.
    pub actual_resources: ResourcesMapping,
}

/// A mapping from a transaction execution resource to its actual usage.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ResourcesMapping(pub HashMap<String, usize>);

/// Contains the failure reason (error code and error message) of an invalid transaction.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct TransactionFailureReason {
    pub code: String,
    pub message: String,
}
