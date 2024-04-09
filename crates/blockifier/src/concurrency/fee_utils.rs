use starknet_api::hash::StarkFelt;

use crate::context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::transactions::ExecutableTransaction;
#[cfg(test)]
#[path = "fee_utils_test.rs"]
mod test;

// We read account balance (sender), write (which starts with read) the account balance. We then do
// the same for the sequencer balance (recipient). The balance is of type `Uint256`, consist of two
// felts (lsb, msb). Hence, storage read values = [account_balance, 0, account_balance, 0,
// sequencer_balance, 0, sequencer_balance, 0]
const STORAGE_READ_SEQUENCER_BALANCE_INDICES: (usize, usize) = (4, 6);
// In concurrency mode we execute the fee transfer with false sequencer balance values.
// This function fixes the call info to have the correct sequencer balance.
pub fn fix_concurrency_fee_transfer_call_info(
    call_info: &mut CallInfo,
    sequencer_balance: StarkFelt,
) {
    assert_eq!(
        call_info.storage_read_values.len(),
        8,
        "Storage read values should have 8 elements"
    );
    assert_eq!(
        call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.0],
        StarkFelt::ZERO,
        "Sequencer balance should be the zero"
    );
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.0] = sequencer_balance;
    assert_eq!(
        call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.1],
        StarkFelt::ZERO,
        "Sequencer balance should be zero"
    );
    call_info.storage_read_values[STORAGE_READ_SEQUENCER_BALANCE_INDICES.1] = sequencer_balance;
}

pub fn create_fee_transfer_call_data<S: StateReader>(
    state: &mut CachedState<S>,
    account_tx: &AccountTransaction,
    concurrency_mode: bool,
) -> CallInfo {
    let block_context =
        BlockContext::create_for_account_testing_with_concurrency_mode(concurrency_mode);
    let mut transactional_state = CachedState::create_transactional(state);
    let execution_info =
        account_tx.execute_raw(&mut transactional_state, &block_context, true, false).unwrap();

    execution_info.fee_transfer_call_info.unwrap()
}
