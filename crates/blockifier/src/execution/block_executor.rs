use std::collections::HashMap;
use std::sync::Arc;

use starknet_api::block::BlockNumber;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::block::{BlockInfo, BlockNumberHashPair};
use crate::context::{BlockContext, ChainInfo};
use crate::execution::bouncer::BouncerInfo;
use crate::execution::errors::BlockExecutionError;
use crate::execution::transaction_executor::TransactionExecutor;
use crate::state::cached_state::{CachedState, CommitmentStateDiff, GlobalContractCache};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader, StateResult};
use crate::transaction::objects::TransactionExecutionInfo;
use crate::transaction::transaction_execution::Transaction;
use crate::versioned_constants::VersionedConstants;

pub type BlockExecutionResult<T> = Result<T, BlockExecutionError>;

pub struct GeneralConfig {
    pub chain_info: ChainInfo,
    pub cairo_resource_fee_weights: Arc<HashMap<String, f64>>,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
}

pub struct BlockExecutor<S: StateReader> {
    pub chain_info: ChainInfo,
    pub versioned_constants: VersionedConstants,
    pub tx_executor: TransactionExecutor<S>,
    pub global_contract_cache: GlobalContractCache,
}

impl<S: StateReader> BlockExecutor<S> {
    pub fn new(
        state_reader: S,
        global_contract_cache_size: usize,
        validate_max_n_steps: u32,
        max_recursion_depth: usize,
        chain_info: ChainInfo,
        old_block_number_and_hash: Option<BlockNumberHashPair>,
        // next_block_info?????????????
        block_info: BlockInfo,
    ) -> BlockExecutionResult<Self> {
        let global_contract_cache = GlobalContractCache::new(global_contract_cache_size);
        let mut state = CachedState::new(state_reader, global_contract_cache.clone());
        let versioned_constants =
            versioned_constants_with_overrides(validate_max_n_steps, max_recursion_depth);
        let block_context = pre_process_block(
            &mut state,
            old_block_number_and_hash,
            block_info,
            chain_info.clone(),
            versioned_constants.clone(),
        )?;
        let tx_executor = TransactionExecutor::new(state, block_context);
        let block_executor =
            Self { chain_info, versioned_constants, tx_executor, global_contract_cache };
        Ok(block_executor)
    }

    // What is this charge fee for??????????????
    pub fn execute_tx(
        &mut self,
        tx: Transaction,
        charge_fee: bool,
    ) -> BlockExecutionResult<(TransactionExecutionInfo, BouncerInfo)> {
        self.tx_executor.execute(tx, charge_fee)
    }

    pub fn execute_batch(
        &mut self,
        batch: impl Iterator<Item = Transaction>,
    ) -> BlockExecutionResult<()> {
        let charge_fee = true;
        for tx in batch {
            self.execute_tx(tx, charge_fee)?;
            self.tx_executor.commit();
            // finalize???
        }
        Ok(())
    }

    pub fn finalize(
        &mut self,
        is_pending_block: bool,
    ) -> (CommitmentStateDiff, Vec<(ClassHash, Vec<usize>)>) {
        log::debug!("Finalizing execution...");
        let (commitment_state_diff, visited_pcs) = self.tx_executor.finalize(is_pending_block);
        let finalized_state = (commitment_state_diff, visited_pcs);
        log::debug!("Finalized execution.");
        finalized_state
    }

    pub fn commit_tx(&mut self) {
        self.tx_executor.commit()
    }

    pub fn abort_tx(&mut self) {
        self.tx_executor.abort()
    }
}

// Block pre-processing.
// Writes the hash of the (current_block_number - N) block under its block number in the dedicated
// contract state, where N=STORED_BLOCK_HASH_BUFFER.
// NOTE: This function must remain idempotent since full nodes can call it for an already updated
// block hash table.
pub fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<BlockNumberHashPair>,
    block_info: BlockInfo,
    chain_info: ChainInfo,
    versioned_constants: VersionedConstants,
) -> StateResult<BlockContext> {
    let should_block_hash_be_provided =
        block_info.block_number >= BlockNumber(constants::STORED_BLOCK_HASH_BUFFER);
    if let Some(BlockNumberHashPair { number: block_number, hash: block_hash }) =
        old_block_number_and_hash
    {
        let block_hash_contract_address =
            ContractAddress::from(constants::BLOCK_HASH_CONTRACT_ADDRESS);
        let block_number_as_storage_key = StorageKey::from(block_number.0);
        state.set_storage_at(
            block_hash_contract_address,
            block_number_as_storage_key,
            block_hash.0,
        )?;
    } else if should_block_hash_be_provided {
        return Err(StateError::OldBlockHashNotProvided);
    }

    Ok(BlockContext { block_info, chain_info, versioned_constants })
}

pub fn versioned_constants_with_overrides(
    validate_max_n_steps: u32,
    max_recursion_depth: usize,
) -> VersionedConstants {
    let mut versioned_constants = VersionedConstants::latest_constants().clone();
    versioned_constants.max_recursion_depth = max_recursion_depth;
    versioned_constants.validate_max_n_steps = validate_max_n_steps;
    versioned_constants
}
