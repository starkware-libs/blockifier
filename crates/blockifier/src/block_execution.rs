use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
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
    let should_block_hash_be_provided =
        block_context_args.block_number >= BlockNumber(constants::STORED_BLOCK_HASH_BUFFER);
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
