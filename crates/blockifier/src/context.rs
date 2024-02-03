use starknet_api::core::{ChainId, ContractAddress};

use crate::block::BlockInfo;
use crate::transaction::objects::FeeType;
use crate::versioned_constants::VersionedConstants;

/// Create via [`crate::block::pre_process_block`] to ensure correctness.
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
pub struct ChainInfo {
    pub chain_id: ChainId,
    pub fee_token_addresses: FeeTokenAddresses,
}

impl ChainInfo {
    pub fn fee_token_address(&self, fee_type: &FeeType) -> ContractAddress {
        self.fee_token_addresses.get_by_fee_type(fee_type)
    }
}

impl Default for ChainInfo {
    fn default() -> Self {
        ChainInfo {
            chain_id: ChainId("0x0".to_string()),
            fee_token_addresses: FeeTokenAddresses::default(),
        }
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
