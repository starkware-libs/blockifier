use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ContractAddress};

use crate::transaction::objects::FeeType;
use crate::versioned_constants::VersionedConstants;

/// Create via [`crate::block_execution::pre_process_block`] to ensure correctness.
#[derive(Clone, Debug)]
pub struct BlockContext {
    pub(crate) block_info: BlockInfo,
    pub(crate) chain_info: ChainInfo,
    pub(crate) versioned_constants: VersionedConstants,
}

impl BlockContext {
    /// Note: Prefer using the recommended constructor methods as detailed in the struct
    /// documentation. This method is intended for internal use and will be deprecated in future
    /// versions.
    pub fn new_unchecked(
        block_info: &BlockInfo,
        chain_info: &ChainInfo,
        versioned_constants: &VersionedConstants,
    ) -> Self {
        BlockContext {
            block_info: block_info.clone(),
            chain_info: chain_info.clone(),
            versioned_constants: versioned_constants.clone(),
        }
    }

    pub fn block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    pub fn chain_info(&self) -> &ChainInfo {
        &self.chain_info
    }
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_number: BlockNumber,
    pub block_timestamp: BlockTimestamp,

    // Fee-related.
    pub sequencer_address: ContractAddress,
    pub gas_prices: GasPrices,
    pub use_kzg_da: bool,
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
