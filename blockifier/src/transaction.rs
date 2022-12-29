pub mod constants;
pub mod errors;
pub mod invoke_transaction;
pub mod objects;
pub mod transaction_utils;

use crate::state::state_api::State;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};

pub trait ExecuteTransaction {
    fn execute(self, state: &mut dyn State)
    -> TransactionExecutionResult<TransactionExecutionInfo>;
}
