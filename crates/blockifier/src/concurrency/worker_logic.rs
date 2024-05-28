use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use num_traits::ToPrimitive;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::Fee;

use super::versioned_state::VersionedStateProxy;
use crate::blockifier::transaction_executor::TransactionExecutorError;
use crate::bouncer::Bouncer;
use crate::concurrency::fee_utils::fill_sequencer_balance_reads;
use crate::concurrency::scheduler::{Scheduler, Task};
use crate::concurrency::utils::lock_mutex_in_array;
use crate::concurrency::versioned_state::ThreadSafeVersionedState;
use crate::concurrency::TxIndex;
use crate::context::BlockContext;
use crate::execution::execution_utils::stark_felt_to_felt;
use crate::fee::fee_utils::get_sequencer_balance_keys;
use crate::state::cached_state::{
    ContractClassMapping, StateChanges, StateMaps, TransactionalState,
};
use crate::state::state_api::{StateReader, UpdatableState};
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{TransactionExecutionInfo, TransactionExecutionResult};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ExecutableTransaction;

#[cfg(test)]
#[path = "worker_logic_test.rs"]
pub mod test;

const EXECUTION_OUTPUTS_UNWRAP_ERROR: &str = "Execution task outputs should not be None.";

#[derive(Debug)]
pub struct ExecutionTaskOutput {
    pub reads: StateMaps,
    pub writes: StateMaps,
    pub contract_classes: ContractClassMapping,
    pub visited_pcs: HashMap<ClassHash, HashSet<usize>>,
    pub result: TransactionExecutionResult<TransactionExecutionInfo>,
}

pub struct WorkerExecutor<'a, S: StateReader> {
    pub scheduler: Scheduler,
    pub state: ThreadSafeVersionedState<S>,
    pub chunk: &'a [Transaction],
    pub execution_outputs: Box<[Mutex<Option<ExecutionTaskOutput>>]>,
    pub block_context: BlockContext,
    pub bouncer: Mutex<&'a mut Bouncer>,
}
impl<'a, S: StateReader> WorkerExecutor<'a, S> {
    pub fn new(
        state: ThreadSafeVersionedState<S>,
        chunk: &'a [Transaction],
        block_context: BlockContext,
        bouncer: Mutex<&'a mut Bouncer>,
    ) -> Self {
        let scheduler = Scheduler::new(chunk.len());
        let execution_outputs =
            std::iter::repeat_with(|| Mutex::new(None)).take(chunk.len()).collect();

        WorkerExecutor { scheduler, state, chunk, execution_outputs, block_context, bouncer }
    }

    pub fn run(&self) {
        let mut task = Task::NoTask;
        loop {
            self.commit_while_possible();
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

    fn commit_while_possible(&self) {
        if let Some(mut transaction_committer) = self.scheduler.try_enter_commit_phase() {
            while let Some(tx_index) = transaction_committer.try_commit() {
                let commit_succeeded = self.commit_tx(tx_index);
                if !commit_succeeded {
                    transaction_committer.halt_scheduler();
                }
            }
        }
    }

    fn execute(&self, tx_index: TxIndex) {
        self.execute_tx(tx_index);
        self.scheduler.finish_execution(tx_index)
    }

    fn execute_tx(&self, tx_index: TxIndex) {
        let mut tx_versioned_state = self.state.pin_version(tx_index);
        let tx = &self.chunk[tx_index];
        let mut transactional_state =
            TransactionalState::create_transactional(&mut tx_versioned_state);
        let validate = true;
        let charge_fee = true;

        let execution_result =
            tx.execute_raw(&mut transactional_state, &self.block_context, charge_fee, validate);

        if execution_result.is_ok() {
            // TODO(Noa, 15/05/2024): use `tx_versioned_state` when we add support to transactional
            // versioned state.
            self.state.pin_version(tx_index).apply_writes(
                &transactional_state.cache.borrow().writes,
                &transactional_state.class_hash_to_class.borrow(),
                &HashMap::default(),
            );
        }

        // Write the transaction execution outputs.
        let tx_reads_writes = transactional_state.cache.take();
        let class_hash_to_class = transactional_state.class_hash_to_class.take();
        // In case of a failed transaction, we don't record its writes and visited pcs.
        let (writes, contract_classes, visited_pcs) = match execution_result {
            Ok(_) => (tx_reads_writes.writes, class_hash_to_class, transactional_state.visited_pcs),
            Err(_) => (StateMaps::default(), HashMap::default(), HashMap::default()),
        };
        let mut execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        *execution_output = Some(ExecutionTaskOutput {
            reads: tx_reads_writes.initial_reads,
            writes,
            contract_classes,
            visited_pcs,
            result: execution_result,
        });
    }

    fn validate(&self, tx_index: TxIndex) -> Task {
        let tx_versioned_state = self.state.pin_version(tx_index);
        let execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let execution_output = execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR);
        let reads = &execution_output.reads;
        let reads_valid = tx_versioned_state.validate_reads(reads);

        let aborted = !reads_valid && self.scheduler.try_validation_abort(tx_index);
        if aborted {
            tx_versioned_state
                .delete_writes(&execution_output.writes, &execution_output.contract_classes);
            self.scheduler.finish_abort(tx_index)
        } else {
            Task::NoTask
        }
    }

    /// Commits a transaction. The commit process is as follows:
    /// 1) Validate the read set.
    ///     * If validation failed, delete the transaction writes and (re-)execute it.
    ///     * Else (validation succeeded), no need to re-execute.
    /// 2) Execution is final.
    ///     * If execution succeeded, ask the bouncer if there is room for the transaction in the
    ///       block.
    ///         - If there is room, fix the call info, update the sequencer balance and commit the
    ///           transaction.
    ///         - Else (no room), do not commit. The block should be closed without the transaction.
    ///     * Else (execution failed), commit the transaction without fixing the call info or
    ///       updating the sequencer balance.
    fn commit_tx(&self, tx_index: TxIndex) -> bool {
        let execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let execution_output_ref = execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR);

        let tx = &self.chunk[tx_index];
        let mut tx_versioned_state = self.state.pin_version(tx_index);

        let reads = &execution_output_ref.reads;
        let reads_valid = tx_versioned_state.validate_reads(reads);

        // First, re-validate the transaction.
        if !reads_valid {
            // Revalidate failed: re-execute the transaction.
            tx_versioned_state.delete_writes(
                &execution_output_ref.writes,
                &execution_output_ref.contract_classes,
            );
            // Release the execution output lock as it is acquired in execution (avoid dead-lock).
            drop(execution_output);

            self.execute_tx(tx_index);
            self.scheduler.finish_execution_during_commit(tx_index);

            let execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
            let read_set = &execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).reads;
            // Another validation after the re-execution for sanity check.
            assert!(tx_versioned_state.validate_reads(read_set));
        } else {
            // Release the execution output lock, since it is has been released in the other flow.
            drop(execution_output);
        }

        // Execution is final.
        let mut execution_output = lock_mutex_in_array(&self.execution_outputs, tx_index);
        let writes = &execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).writes;
        let reads = &execution_output.as_ref().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).reads;
        let tx_state_changes_keys = StateChanges::from(writes.diff(reads)).into_keys();
        let tx_result =
            &mut execution_output.as_mut().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR).result;

        let tx_context = Arc::new(self.block_context.to_tx_context(tx));
        if let Ok(tx_execution_info) = tx_result.as_mut() {
            // Ask the bouncer if there is room for the transaction in the block.
            let bouncer_result = self.bouncer.lock().expect("Bouncer lock failed.").try_update(
                &tx_versioned_state,
                &tx_state_changes_keys,
                &tx_execution_info.summarize(),
                &tx_execution_info.actual_resources,
            );
            if let Err(error) = bouncer_result {
                match error {
                    TransactionExecutorError::BlockFull => return false,
                    TransactionExecutorError::TransactionExecutionError(
                        TransactionExecutionError::TransactionTooLarge,
                    ) => {
                        // TransactionTooLarge error - revise the execution result, delete writes
                        // and commit.
                        // TODO(Avi, 20/6/2024): Move TransactionTooLarge inside execute_raw.
                        let old_execution_output =
                            execution_output.take().expect(EXECUTION_OUTPUTS_UNWRAP_ERROR);
                        tx_versioned_state.delete_writes(
                            &old_execution_output.writes,
                            &old_execution_output.contract_classes,
                        );

                        *execution_output = Some(ExecutionTaskOutput {
                            reads: old_execution_output.reads,
                            writes: StateMaps::default(),
                            contract_classes: HashMap::default(),
                            visited_pcs: HashMap::default(),
                            result: Err(TransactionExecutionError::TransactionTooLarge),
                        });

                        // Signal to the scheduler that the execution output has been revised, so
                        // higher transactions should be re-validated.
                        self.scheduler.finish_execution_during_commit(tx_index);

                        return true;
                    }
                    _ => {
                        // TODO(Avi, 01/07/2024): Consider propagating the error.
                        panic!("Bouncer update failed. {error:?}: {error}");
                    }
                }
            }
            // Update the sequencer balance (in state + call info).
            if tx_context.tx_info.sender_address()
                == self.block_context.block_info.sequencer_address
            {
                // When the sequencer is the sender, we use the sequential (full) fee transfer.
                return true;
            }

            let mut next_tx_versioned_state = self.state.pin_version(tx_index + 1);
            let (sequencer_balance_value_low, sequencer_balance_value_high) =
                next_tx_versioned_state
                    .get_fee_token_balance(
                        tx_context.block_context.block_info.sequencer_address,
                        tx_context.fee_token_address(),
                    )
                    // TODO(barak, 01/07/2024): Consider propagating the error.
                    .unwrap_or_else(|error| {
                        panic!(
                            "Access to storage failed. Probably due to a bug in Papyrus. {error:?}: {error}"
                        )
                    });

            if let Some(fee_transfer_call_info) = tx_execution_info.fee_transfer_call_info.as_mut()
            {
                // Fix the transfer call info.
                fill_sequencer_balance_reads(
                    fee_transfer_call_info,
                    sequencer_balance_value_low,
                    sequencer_balance_value_high,
                );
            }
            add_fee_to_sequencer_balance(
                tx_context.fee_token_address(),
                &mut tx_versioned_state,
                tx_execution_info.actual_fee,
                &self.block_context,
                sequencer_balance_value_low,
                sequencer_balance_value_high,
            );
            // Changing the sequencer balance storage cell does not trigger (re-)validation of
            // the next transactions.
        }

        true
    }
}

// Utilities.

fn add_fee_to_sequencer_balance(
    fee_token_address: ContractAddress,
    tx_versioned_state: &mut VersionedStateProxy<impl StateReader>,
    actual_fee: Fee,
    block_context: &BlockContext,
    sequencer_balance_value_low: StarkFelt,
    sequencer_balance_value_high: StarkFelt,
) {
    let sequencer_balance_low_as_u128 = stark_felt_to_felt(sequencer_balance_value_low)
        .to_u128()
        .expect("sequencer balance low should be u128");
    let sequencer_balance_high_as_u128 = stark_felt_to_felt(sequencer_balance_value_high)
        .to_u128()
        .expect("sequencer balance high should be u128");
    let (new_value_low, carry) = sequencer_balance_low_as_u128.overflowing_add(actual_fee.0);
    let (new_value_high, carry) = sequencer_balance_high_as_u128.overflowing_add(carry.into());
    assert!(
        !carry,
        "The sequencer balance overflowed when adding the fee. This should not happen."
    );
    let (sequencer_balance_key_low, sequencer_balance_key_high) =
        get_sequencer_balance_keys(block_context);
    let writes = StateMaps {
        storage: HashMap::from([
            ((fee_token_address, sequencer_balance_key_low), stark_felt!(new_value_low)),
            ((fee_token_address, sequencer_balance_key_high), stark_felt!(new_value_high)),
        ]),
        ..StateMaps::default()
    };
    tx_versioned_state.apply_writes(&writes, &ContractClassMapping::default(), &HashMap::default());
}
