use std::collections::HashMap;

use starknet_api::{Fee, StarkFelt};

// TODO(Adi, 10/12/2022): Change to the Python class definition, once the 'execute' function of
// 'CallEntryPoint' returns a CallInfo.
pub type CallInfo = Vec<StarkFelt>;

// TODO(Adi, 10/12/2022): Add a 'transaction_type' field.
/// Contains the information gathered by the execution of a transaction.
#[derive(Debug, Eq, PartialEq)]
pub struct TransactionExecutionInfo {
    /// Transaction-specific validation call info.
    pub validate_info: CallInfo,
    /// Transaction-specific execution call info, None for Declare.
    pub call_info: Option<CallInfo>,
    /// Fee transfer call info, executed by the BE for account contract transactions.
    pub fee_transfer_info: CallInfo,
    /// The actual fee that was charged (in Wei).
    pub actual_fee: Fee,
    /// Actual resources the transaction is charged for, including L1 gas and OS additional
    /// resources estimation.
    pub actual_resources: ResourcesMapping,
}

/// A mapping from a transaction resource to its actual usage.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ResourcesMapping(pub HashMap<String, usize>);
