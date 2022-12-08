pub mod constants;
pub mod errors;
pub mod invoke_transaction;
pub mod objects;
pub mod transaction_utils;

use crate::cached_state::{CachedState, DictStateReader};
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::TransactionExecutionInfo;

pub trait ExecuteTransaction {
    fn execute(
        &self,
        state: CachedState<DictStateReader>,
    ) -> Result<TransactionExecutionInfo, TransactionExecutionError>;
}
