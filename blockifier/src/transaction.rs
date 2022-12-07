pub mod constants;
pub mod execution_objects;
pub mod invoke_transaction;
pub mod transaction_errors;
pub mod transaction_utils;

#[cfg(test)]
pub mod invoke_transaction_test;

use crate::transaction::execution_objects::TransactionExecutionInfo;
use crate::transaction::transaction_errors::TransactionExecutionError;

pub trait ExecuteTransaction {
    fn execute(&self) -> Result<TransactionExecutionInfo, TransactionExecutionError>;
}
