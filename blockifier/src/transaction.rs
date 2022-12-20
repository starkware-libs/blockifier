pub mod constants;
pub mod errors;
pub mod invoke_transaction;
pub mod objects;
pub mod transaction_utils;

use crate::state::cached_state::{CachedState, DictStateReader};
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};

pub trait ExecuteTransaction {
    fn execute(
        &self,
        state: &mut CachedState<DictStateReader>,
    ) -> TransactionExecutionResult<TransactionExecutionInfo>;
}
