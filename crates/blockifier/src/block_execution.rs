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

pub struct BlockNumberAndHash {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
}

impl BlockNumberAndHash {
    pub fn new(block_number: u64, block_hash: StarkFelt) -> BlockNumberAndHash {
        BlockNumberAndHash {
            block_number: BlockNumber(block_number),
            block_hash: BlockHash(block_hash),
        }
    }
}

// Block pre-processing.
// Writes the hash of the (current_block_number - N) block under its block number in the dedicated
// contract state, where N=STORED_BLOCK_HASH_BUFFER.
// NOTE: This function must remain idempotent since full nodes can call it for an already updated
// block hash table.
pub fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<BlockNumberAndHash>,
    block_context_args: BlockContextArgs,
) -> StateResult<BlockContext> {
    match old_block_number_and_hash {
        Some(BlockNumberAndHash { block_number, block_hash }) => {
            state.set_storage_at(
                ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                    .expect("Failed to convert `BLOCK_HASH_CONTRACT_ADDRESS` to ContractAddress."),
                StorageKey::try_from(StarkFelt::from(block_number.0))
                    .expect("Failed to convert BlockNumber to StorageKey."),
                block_hash.0,
            )?;
        }
        None if block_context_args.block_number >= BlockNumber(STORED_BLOCK_HASH_BUFFER) => {
            // We allow None value for block_number < STORED_BLOCK_HASH_BUFFER because we update
            // the hash table in STORED_BLOCK_HASH_BUFFER blocks delay. This is done since the
            // hash computation has a delay.
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
