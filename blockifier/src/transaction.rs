pub mod constants;
pub mod errors;
pub mod invoke_transaction;
pub mod objects;
pub mod transaction_utils;

use crate::execution::entry_point::StateRC;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};

pub trait ExecuteTransaction {
    fn execute(&self, state: StateRC) -> TransactionExecutionResult<TransactionExecutionInfo>;
}
