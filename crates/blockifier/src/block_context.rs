use std::collections::HashMap;
use std::sync::Arc;

use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

use crate::block_execution::BlockContextArgs;
use crate::transaction::objects::FeeType;

#[derive(Clone, Debug)]
pub struct BlockContext {
    // At least one of the following fields should be pub(crate) to make the constructore private.
    pub(crate) block_info: BlockInfo,
    pub chain_info: ChainInfo,
}

impl BlockContext {
    pub fn new_unchecked(block_context_args: BlockContextArgs) -> Self {
        BlockContext {
            block_info: BlockInfo {
                block_number: block_context_args.block_number,
                block_timestamp: block_context_args.block_timestamp,
                sequencer_address: block_context_args.sequencer_address,
                vm_resource_fee_cost: block_context_args.vm_resource_fee_cost,
                gas_prices: block_context_args.gas_prices,
                use_kzg_da: block_context_args.use_kzg_da,
                invoke_tx_max_n_steps: block_context_args.invoke_tx_max_n_steps,
                validate_max_n_steps: block_context_args.validate_max_n_steps,
                max_recursion_depth: block_context_args.max_recursion_depth,
            },
            chain_info: ChainInfo {
                chain_id: block_context_args.chain_id,
                fee_token_addresses: block_context_args.fee_token_addresses,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,

    // Fee-related.
    pub sequencer_address: ContractAddress,
    pub vm_resource_fee_cost: Arc<HashMap<String, f64>>,
    pub gas_prices: GasPrices,
    pub use_kzg_da: bool,

    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
}

#[derive(Clone, Debug)]
pub struct ChainInfo {
    pub chain_id: ChainId,
    pub fee_token_addresses: FeeTokenAddresses,
}

impl ChainInfo {
    pub fn fee_token_address(&self, fee_type: &FeeType) -> ContractAddress {
        self.fee_token_addresses.get_by_fee_type(fee_type)
    }
}

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug, Default)]
pub struct GasPrices {
    pub eth_l1_gas_price: u128,       // In wei.
    pub strk_l1_gas_price: u128,      // In fri.
    pub eth_l1_data_gas_price: u128,  // In wei.
    pub strk_l1_data_gas_price: u128, // In fri.
}

impl GasPrices {
    pub fn get_gas_price_by_fee_type(&self, fee_type: &FeeType) -> u128 {
        match fee_type {
            FeeType::Strk => self.strk_l1_gas_price,
            FeeType::Eth => self.eth_l1_gas_price,
        }
    }

    pub fn get_data_gas_price_by_fee_type(&self, fee_type: &FeeType) -> u128 {
        match fee_type {
            FeeType::Strk => self.strk_l1_data_gas_price,
            FeeType::Eth => self.eth_l1_data_gas_price,
        }
    }
}
