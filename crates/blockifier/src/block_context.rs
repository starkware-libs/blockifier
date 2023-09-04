use std::collections::HashMap;
use std::sync::Arc;

use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

#[derive(Clone, Debug)]
pub struct BlockContext {
    pub chain_id: ChainId,
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,

    // Fee-related.
    pub sequencer_address: ContractAddress,
    pub deprecated_fee_token_address: ContractAddress,
    pub fee_token_address: ContractAddress,
    pub vm_resource_fee_cost: Arc<HashMap<String, f64>>,
    pub eth_l1_gas_price: u128, // In wei.
    // TODO(Amos, 01/09/2023): NEW_TOKEN_SUPPORT use this gas price for V3 txs.
    pub strk_l1_gas_price: u128, // In STRK.

    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
}
