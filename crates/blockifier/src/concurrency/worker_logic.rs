use std::sync::Arc;

use cairo_felt::Felt252;

use super::versioned_state_proxy::VersionedStateProxy;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::context::TransactionContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::state::cached_state::CachedState;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::objects::TransactionExecutionInfo;

fn _add_fee_to_sequencer_balance(
    tx_context: Arc<TransactionContext>,
    pinned_versioned_state: &VersionedStateProxy<impl StateReader>,
    tx_info: &TransactionExecutionInfo,
    transactional_state: &mut CachedState<impl StateReader>,
) -> StateResult<()> {
    let seq_balance_key = get_fee_token_var_address(tx_context.fee_token_address());
    let seq_balance_value =
        pinned_versioned_state.get_storage_at(tx_context.fee_token_address(), seq_balance_key)?;
    let value = stark_felt_to_felt(seq_balance_value) + Felt252::from(tx_info.actual_fee.0);
    transactional_state.set_storage_at(
        tx_context.fee_token_address(),
        seq_balance_key,
        felt_to_stark_felt(&value),
    )?;
    Ok(())
}
