use rstest::fixture;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};

use crate::concurrency::versioned_state_proxy::{ThreadSafeVersionedState, VersionedState};
use crate::context::BlockContext;
use crate::execution::call_info::CallInfo;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateReader;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::transactions::ExecutableTransaction;

// Public Consts.

pub const DEFAULT_CHUNK_SIZE: usize = 64;

// Fixtures.

const TEST_CONTRACT_ADDRESS: &str = "0x18031991";

#[fixture]
pub fn contract_address() -> ContractAddress {
    contract_address!(TEST_CONTRACT_ADDRESS)
}

// Macros.

#[macro_export]
macro_rules! default_scheduler {
    ($chunk_size:ident : $chunk:expr , $($field:ident $(: $value:expr)?),+ $(,)?) => {
        Scheduler {
            $chunk_size: $chunk,
            $($field $(: $value.into())?,)*
            tx_statuses: std::iter::repeat_with(|| std::sync::Mutex::new(
                    $crate::concurrency::scheduler::TransactionStatus::ReadyToExecute
                ))
                .take($chunk)
                .collect(),
            ..Default::default()
        }
    };
    ($chunk_size:ident $(, $field:ident $(: $value:expr)?),+ $(,)?) => {
        Scheduler {
            $chunk_size,
            $($field $(: $value.into())?,)*
            tx_statuses: std::iter::repeat_with(|| std::sync::Mutex::new(
                    $crate::concurrency::scheduler::TransactionStatus::ReadyToExecute
                ))
                .take($chunk_size)
                .collect(),
            ..Default::default()
        }
    };
}

// Concurrency constructors.

// TODO(meshi, 01/06/2024): Consider making this a macro.
pub fn safe_versioned_state_for_testing(
    block_state: DictStateReader,
) -> ThreadSafeVersionedState<DictStateReader> {
    ThreadSafeVersionedState::new(VersionedState::new(block_state))
}

// Utils.

// Note: this function does not mutate the state.
pub fn create_fee_transfer_call_info<S: StateReader>(
    state: &mut CachedState<S>,
    account_tx: &AccountTransaction,
    concurrency_mode: bool,
) -> CallInfo {
    let block_context =
        BlockContext::create_for_account_testing_with_concurrency_mode(concurrency_mode);
    let mut transactional_state = CachedState::create_transactional(state);
    let charge_fee = true;
    let validate = true;
    let execution_info = account_tx
        .execute_raw(&mut transactional_state, &block_context, charge_fee, validate)
        .unwrap();

    let execution_info = execution_info.fee_transfer_call_info.unwrap();
    transactional_state.abort();
    execution_info
}
