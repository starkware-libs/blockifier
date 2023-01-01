pub mod constants;
pub mod errors;
pub mod invoke_transaction;
pub mod objects;
pub mod transaction_utils;

use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};

pub trait ExecuteTransaction<SR: StateReader> {
    fn execute(
        self,
        state: &mut CachedState<SR>,
    ) -> TransactionExecutionResult<TransactionExecutionInfo>;
}
