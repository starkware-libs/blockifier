use std::collections::HashMap;
use std::sync::Arc;

use starknet_api::block::{BlockHash, BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::block_context::{BlockContext, BlockInfo, ChainInfo, FeeTokenAddresses, GasPrices};
use crate::state::state_api::{State, StateResult};

#[cfg(test)]
#[path = "block_execution_test.rs"]
pub mod test;

pub struct BlockContextArgs {
    pub chain_id: ChainId,
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,
    pub sequencer_address: ContractAddress,
    pub fee_token_addresses: FeeTokenAddresses,
    pub vm_resource_fee_cost: Arc<HashMap<String, f64>>,
    pub use_kzg_da: bool,
    pub gas_prices: GasPrices,
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
}

impl Default for BlockContextArgs {
    fn default() -> Self {
        Self {
            chain_id: ChainId("0x0".to_string()),
            block_number: BlockNumber::default(),
            block_timestamp: BlockTimestamp::default(),
            sequencer_address: ContractAddress::default(),
            fee_token_addresses: FeeTokenAddresses::default(),
            vm_resource_fee_cost: Default::default(),
            use_kzg_da: false,
            gas_prices: GasPrices::default(),
            invoke_tx_max_n_steps: 0,
            validate_max_n_steps: 0,
            max_recursion_depth: 0,
        }
    }
}

pub struct BlockNumberAndHash {
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
}

// Block pre-processing.
// Writes the hash of the (current_block_number - N) block under its block number in the dedicated
// contract state, where N=STORED_BLOCK_HASH_BUFFER.
// NOTE: This function must remain idempotent since full nodes can call it for an already updated
// block hash table.
pub fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: BlockNumberAndHash,
    block_context_args: BlockContextArgs,
) -> StateResult<BlockContext> {
    state.set_storage_at(
        ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
            .expect("Failed to convert `BLOCK_HASH_CONTRACT_ADDRESS` to ContractAddress."),
        StorageKey::try_from(StarkFelt::from(old_block_number_and_hash.block_number.0))
            .expect("Failed to convert BlockNumber to StorageKey."),
        old_block_number_and_hash.block_hash.0,
    )?;
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
