use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants::{self, STORED_BLOCK_HASH_BUFFER};
use crate::block_context::{BlockContext, BlockContextArgs, BlockInfo, ChainInfo};
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateResult};

#[cfg(test)]
#[path = "block_execution_test.rs"]
pub mod test;

pub struct BlockNumberHashPair {
    pub number: BlockNumber,
    pub hash: BlockHash,
}

impl BlockNumberHashPair {
    pub fn new(block_number: u64, block_hash: StarkFelt) -> BlockNumberHashPair {
        BlockNumberHashPair { number: BlockNumber(block_number), hash: BlockHash(block_hash) }
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
    block_context_args: BlockContextArgs,
) -> StateResult<BlockContext> {
    match old_block_number_and_hash {
        Some(BlockNumberHashPair { number: block_number, hash: block_hash }) => {
            state.set_storage_at(
                ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                    .expect("Failed to convert `BLOCK_HASH_CONTRACT_ADDRESS` to ContractAddress."),
                StorageKey::try_from(StarkFelt::from(block_number.0))
                    .expect("Failed to convert BlockNumber to StorageKey."),
                block_hash.0,
            )?;
        }
        None if block_context_args.block_number >= BlockNumber(STORED_BLOCK_HASH_BUFFER) => {
            // For the first STORED_BLOCK_HASH_BUFFER blocks, the old block hash is not available.
            return Err(StateError::OldBlockHashNotProvided);
        }
        None => {}
    }

    let block_context = BlockContext {
        block_info: BlockInfo {
            block_number: block_context_args.block_number,
            block_timestamp: block_context_args.block_timestamp,
            sequencer_address: block_context_args.sequencer_address,
            vm_resource_fee_cost: block_context_args.vm_resource_fee_cost,
            use_kzg_da: block_context_args.use_kzg_da,
            gas_prices: block_context_args.gas_prices,
            invoke_tx_max_n_steps: block_context_args.invoke_tx_max_n_steps,
            validate_max_n_steps: block_context_args.validate_max_n_steps,
            max_recursion_depth: block_context_args.max_recursion_depth,
        },
        chain_info: ChainInfo {
            chain_id: block_context_args.chain_id,
            fee_token_addresses: block_context_args.fee_token_addresses,
        },
    };

    Ok(block_context)
}
