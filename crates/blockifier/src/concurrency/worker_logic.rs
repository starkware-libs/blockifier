use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Mutex;

use cairo_felt::Felt252;
use num_traits::Bounded;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::Fee;

use super::versioned_state_proxy::VersionedStateProxy;
use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::utils::lock_mutex_in_array;
use crate::concurrency::versioned_state_proxy::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::state::cached_state::{CachedState, ContractClassMapping, StateMaps};
use crate::state::state_api::StateReader;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

#[cfg(test)]
#[path = "worker_logic_test.rs"]
pub mod test;

fn _add_fee_to_sequencer_balance(
    fee_token_address: ContractAddress,
    tx_versioned_state: &VersionedStateProxy<impl StateReader>,
    actual_fee: &Fee,
    sequencer_keys: (StorageKey, StorageKey),
    sequencer_values: (StarkFelt, StarkFelt),
) {
    let felt_fee = Felt252::from(actual_fee.0);
    let new_value_low = stark_felt_to_felt(sequencer_values.0) + felt_fee.clone();
    let overflow = stark_felt_to_felt(sequencer_values.0) > Felt252::max_value() - felt_fee;
    let new_value_high = if overflow {
        stark_felt_to_felt(sequencer_values.1) + Felt252::from(1_u8)
    } else {
        stark_felt_to_felt(sequencer_values.1)
    };

    let writes = StateMaps {
        storage: HashMap::from([
            ((fee_token_address, sequencer_keys.0), felt_to_stark_felt(&new_value_low)),
            ((fee_token_address, sequencer_keys.1), felt_to_stark_felt(&new_value_high)),
        ]),
        ..StateMaps::default()
    };
    tx_versioned_state.apply_writes(&writes, &ContractClassMapping::default());
}

#[derive(Debug)]
pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

pub struct WorkerExecutor<S: StateReader> {
    pub scheduler: Scheduler,
    pub state: ThreadSafeVersionedState<S>,
    pub chunk: Box<[Transaction]>,
    pub execution_outputs: Box<[Mutex<Option<ExecutionTaskOutput>>]>,
    pub block_context: BlockContext,
}
impl<S: StateReader> WorkerExecutor<S> {
    pub fn run(&self) {
        let mut task = Task::NoTask;
        loop {
            task = match task {
                Task::ExecutionTask(tx_index) => {
                    self.execute(tx_index);
                    Task::NoTask
                }
                Task::ValidationTask(tx_index) => self.validate(tx_index),
                Task::NoTask => self.scheduler.next_task(),
                Task::Done => break,
            };
        }
    }

    fn execute(&self, tx_index: TxIndex) {
        self.execute_tx(tx_index);
        self.scheduler.finish_execution(tx_index)
    }

    fn execute_tx(&self, tx_index: TxIndex) {
        let tx_versioned_state = self.state.pin_version(tx_index);
        let tx = &self.chunk[tx_index];
        // TODO(Noa, 15/05/2024): remove the redundant cached state.
        let mut tx_state = CachedState::new(tx_versioned_state);
        let mut transactional_state = CachedState::create_transactional(&mut tx_state);
        let validate = true;
        let charge_fee = true;

        let execution_result =
            tx.execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate);

        if execution_result.is_ok() {
            let class_hash_to_class = transactional_state.class_hash_to_class.borrow();
            // TODO(Noa, 15/05/2024): use `tx_versioned_state` when we add support to transactional
            // versioned state.
            self.state
                .pin_version(tx_index)
                .apply_writes(&transactional_state.cache.borrow().writes, &class_hash_to_class);
        }

        // Write the transaction execution outputs.
        let tx_reads_writes = transactional_state.cache.take();
        // In case of a failed transaction, we don't record its writes and visited pcs.
        let (writes, visited_pcs) = match execution_result {
            Ok(_) => (tx_reads_writes.writes, transactional_state.visited_pcs),
            Err(_) => (StateMaps::default(), HashMap::default()),
        };
        let mut execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        *execution_output = Some(ExecutionTaskOutput {
            reads: tx_reads_writes.initial_reads,
            writes,
            visited_pcs,
            result: execution_result,
        });
    }

    fn validate(&self, _tx_index: TxIndex) -> Task {
        todo!();
    }
}
