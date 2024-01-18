use starknet_api::core::{ChainId, ContractAddress};

use crate::block::BlockInfo;
use crate::transaction::objects::FeeType;
use crate::versioned_constants::VersionedConstants;

#[derive(Clone, Debug)]
pub struct BlockContext {
    pub block_info: BlockInfo,
    pub chain_info: ChainInfo,
    pub versioned_constants: VersionedConstants,
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
