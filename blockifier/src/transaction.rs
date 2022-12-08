pub mod invoke_transaction;

#[cfg(test)]
pub mod invoke_transaction_test;

use crate::transaction::execution_objects::TransactionExecutionInfo;
use crate::transaction::transaction_errors::TransactionExecutionError;

pub trait ExecuteTransaction {
    fn execute(&self) -> Result<TransactionExecutionInfo, TransactionExecutionError>;
}
