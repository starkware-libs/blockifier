pub mod constants;
pub mod errors;
pub mod invoke_transaction;
pub mod objects;
pub mod transaction_utils;

use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionInfo;

pub trait ExecuteTransaction {
    fn execute(&self) -> Result<TransactionExecutionInfo, TransactionExecutionError>;
}
