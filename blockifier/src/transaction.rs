pub mod invoke_transaction;

use crate::transaction::objects::TransactionExecutionInfo;
use crate::transaction::transaction_errors::TransactionExecutionError;

pub trait ExecuteTransaction {
    fn execute(&self) -> Result<TransactionExecutionInfo, TransactionExecutionError>;
}
