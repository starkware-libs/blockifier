use std::collections::HashMap;
use std::sync::Arc;

use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

use crate::transaction::objects::FeeType;

#[derive(Clone, Debug)]
pub struct BlockContext {
    pub chain_id: ChainId,
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,

    // Fee-related.
    pub sequencer_address: ContractAddress,
    pub fee_token_addresses: FeeTokenAddresses,
    pub vm_resource_fee_cost: Arc<HashMap<String, f64>>,
    pub gas_prices: GasPrices,

    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
}

impl BlockContext {
    pub fn fee_token_address(&self, fee_type: &FeeType) -> ContractAddress {
        self.fee_token_addresses.get_by_fee_type(fee_type)
    }
}

#[derive(Clone, Debug)]
pub struct FeeTokenAddresses {
    pub strk_fee_token_address: ContractAddress,
    pub eth_fee_token_address: ContractAddress,
}

impl FeeTokenAddresses {
    pub fn get_by_fee_type(&self, fee_type: &FeeType) -> ContractAddress {
        match fee_type {
            FeeType::Strk => self.strk_fee_token_address,
            FeeType::Eth => self.eth_fee_token_address,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GasPrices {
    pub eth_l1_gas_price: u128, // In wei.
    // TODO(Amos, 01/09/2023): NEW_TOKEN_SUPPORT use this gas price for V3 txs.
    pub strk_l1_gas_price: u128, // In STRK.
}

impl GasPrices {
    pub fn get_by_fee_type(&self, fee_type: &FeeType) -> u128 {
        match fee_type {
            FeeType::Strk => self.strk_l1_gas_price,
            FeeType::Eth => self.eth_l1_gas_price,
        }
    }
}
