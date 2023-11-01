use std::collections::{HashMap, HashSet};

use cairo_felt::Felt252;
use itertools::concat;
use num_traits::Pow;
use starknet_api::core::{ClassHash, ContractAddress, Nonce};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::{Fee, TransactionHash, TransactionSignature, TransactionVersion};

use crate::execution::entry_point::CallInfo;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::transaction::constants::SIMULATE_VERSION_BASE_BIT;
use crate::transaction::errors::TransactionExecutionError;

pub type TransactionExecutionResult<T> = Result<T, TransactionExecutionError>;

/// Contains the account information of the transaction (outermost call).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountTransactionContext {
    pub transaction_hash: TransactionHash,
    pub max_fee: Fee,
    pub version: TransactionVersion,
    pub signature: TransactionSignature,
    pub nonce: Nonce,
    pub sender_address: ContractAddress,
    pub simulate: bool,
}

impl AccountTransactionContext {
    pub fn is_v0(&self) -> bool {
        self.version == TransactionVersion(stark_felt!(0_u8))
    }

    pub fn signed_version(&self) -> TransactionVersion {
        if !self.simulate {
            return self.version;
        }

        let simulate_version_base = Pow::pow(Felt252::from(2_u8), SIMULATE_VERSION_BASE_BIT);
        let simulate_version = simulate_version_base + stark_felt_to_felt(self.version.0);
        TransactionVersion(felt_to_stark_felt(&simulate_version))
    }
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
