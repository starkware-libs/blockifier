use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::{Arc, Mutex, MutexGuard};

use cairo_felt::Felt252;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::transaction::Fee;

use super::versioned_state_proxy::{ThreadSafeVersionedState, VersionedStateProxy};
use super::TxIndex;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::concurrency::fee_utils::fill_sequencer_balance_reads;
use crate::concurrency::scheduler::{Scheduler, Task};
use crate::context::BlockContext;
use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{CachedState, StateMaps};
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

#[derive(Debug)]
pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

pub fn lock_mutex_in_array<T: Debug>(array: &[Mutex<T>], tx_index: TxIndex) -> MutexGuard<'_, T> {
    array[tx_index].lock().unwrap_or_else(|error| {
        panic!("Cell of transaction index {} is poisoned. Data: {:?}.", tx_index, *error.get_ref())
    })
}

fn finalize_commit(
    fee_token_adress: ContractAddress,
    pinned_versioned_state: &VersionedStateProxy<impl StateReader>,
    actual_fee: &Fee,
    transactional_state: &mut CachedState<impl StateReader>,
) -> StateResult<()> {
    let sequencer_balance_key = get_fee_token_var_address(fee_token_adress);
    let sequencer_balance_value =
        pinned_versioned_state.get_storage_at(fee_token_adress, sequencer_balance_key)?;
    let value = stark_felt_to_felt(sequencer_balance_value) + Felt252::from(actual_fee.0);
    transactional_state.set_storage_at(
        fee_token_adress,
        sequencer_balance_key,
        felt_to_stark_felt(&value),
    )?;
    Ok(())
}


pub struct WorkersExecutor<S: StateReader> {
    pub scheduler: Scheduler,
    pub state: ThreadSafeVersionedState<S>,
    pub chunk: Box<[Transaction]>,
    pub execution_outputs: Box<[Mutex<Option<ExecutionTaskOutput>>]>,
    pub block_context: BlockContext,
}

impl<S: StateReader> WorkersExecutor<S> {
    pub fn run(&self) {
        let scheduler = &self.scheduler;
        let mut task = Task::NoTask;
        loop {
            task = match task {
                Task::ExecutionTask(tx_index) => {
                    self.execute(tx_index);
                    Task::NoTask
                }
                Task::ValidationTask(tx_index) => self.validate(tx_index),
                Task::NoTask => scheduler.next_task(),
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

    pub fn try_commit_transaction(&mut self, tx_index: TxIndex) -> StateResult<bool> {
        let execution_task_outputs = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let read_set = &execution_task_outputs.as_ref().unwrap().reads;
        let mut execution_task_outputs = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let result_tx_info = &mut execution_task_outputs.as_mut().unwrap().result;

        let tx = &self.chunk[tx_index];
        let versioned_state = &self.state;
        // TODO(meshi 20/05/2024): remove the redundant cached state.
        let mut cached_state = CachedState::from(versioned_state.pin_version(tx_index));
        let mut transactional_state = CachedState::create_transactional(&mut cached_state);
        let tx_versioned_state = versioned_state.pin_version(tx_index);

        // First, re-validate the transaction.
        if !tx_versioned_state.validate_reads(read_set) {
            // Revalidate failed: re-execute the transaction, and commit.

            // let new_execution_context = ConcurrentExecutionContext {
            //     block_context: BlockContext{concurrency_mode: false, ..block_context.clone()},
            //     .. execution_context.clone()
            // };

            self.block_context =
                BlockContext { concurrency_mode: true, ..self.block_context.clone() };

            self.execute_tx(tx_index);
            let result_tx_info = &mut execution_task_outputs.as_mut().unwrap().result;
            if result_tx_info.is_err() {
                // TODO(Meshi, 01/06/2024): Rvert the chanches of the execution before the
                // re-execution.
                todo!()
            }
            // Another validation after the re-execution for sanity check.
            assert!(tx_versioned_state.validate_reads(read_set));
            // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
            return Ok(true);
        }
        // Revalidate succeeded.
        if result_tx_info.is_err() {
            // Transaction failed and successfully committed.
            return Ok(true);
        }
        let tx_context = Arc::new(self.block_context.to_tx_context(tx));
        // Fix the sequencer balance.
        // There is no need to fix the balance when the sequencer transfers fee to itself, since we
        // use the sequential fee transfer in this case.
        if tx_context.tx_info.sender_address() != self.block_context.block_info.sequencer_address {
            let (sequencer_balance_key_low, sequencer_balance_key_high) =
                get_sequencer_balance_keys(&tx_context.block_context);
            let sequencer_balance_low = tx_versioned_state
                .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_low)?;
            let sequencer_balance_high = tx_versioned_state
                .get_storage_at(tx_context.fee_token_address(), sequencer_balance_key_high)?;

            let tx_info =
                result_tx_info.as_mut().expect("Transaction info should not be an error here.");
            if let Some(fee_transfer_call_info) = tx_info.fee_transfer_call_info.as_mut() {
                // Fix the transfer call info.
                fill_sequencer_balance_reads(
                    fee_transfer_call_info,
                    sequencer_balance_low,
                    sequencer_balance_high,
                );

                // Update the sequencer balance in the storage.
                finalize_commit(
                    tx_context.fee_token_address(),
                    &tx_versioned_state,
                    &tx_info.actual_fee,
                    &mut transactional_state,
                )?;
            }
        }
        // TODO(Meshi, 01/06/2024): check if this is also needed in the bouncer.
        Ok(true)
    }
}