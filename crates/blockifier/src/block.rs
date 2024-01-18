use starknet_api::block::{BlockHash, BlockNumber, BlockTimestamp};
use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;

use crate::abi::constants;
use crate::state::state_api::{State, StateResult};
use crate::transaction::objects::FeeType;

#[cfg(test)]
#[path = "block_test.rs"]
pub mod block_test;

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

// Block pre-processing.
// Writes the hash of the (current_block_number - N) block under its block number in the dedicated
// contract state, where N=STORED_BLOCK_HASH_BUFFER.
pub fn pre_process_block(
    state: &mut dyn State,
    old_block_number_and_hash: Option<(BlockNumber, BlockHash)>,
) -> StateResult<()> {
    if let Some((block_number, block_hash)) = old_block_number_and_hash {
        state.set_storage_at(
            ContractAddress::try_from(StarkFelt::from(constants::BLOCK_HASH_CONTRACT_ADDRESS))
                .expect("Failed to convert `BLOCK_HASH_CONTRACT_ADDRESS` to ContractAddress."),
            StorageKey::try_from(StarkFelt::from(block_number.0))
                .expect("Failed to convert BlockNumber to StorageKey."),
            block_hash.0,
        )?;
    }

    Ok(())
}
