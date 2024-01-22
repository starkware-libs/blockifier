use starknet_api::core::{ChainId, ContractAddress};

use crate::block::BlockInfo;
use crate::transaction::objects::{FeeType, TransactionInfo, TransactionInfoCreator};
use crate::versioned_constants::VersionedConstants;

#[derive(Clone, Debug)]
pub struct TransactionContext {
    pub block_context: BlockContext,
    pub tx_info: TransactionInfo,
}

#[derive(Clone, Debug)]
pub struct BlockContext {
    pub block_info: BlockInfo,
    pub chain_info: ChainInfo,
    pub versioned_constants: VersionedConstants,
}

impl BlockContext {
    pub fn to_tx_context(
        &self,
        tx_info_creator: &impl TransactionInfoCreator,
    ) -> TransactionContext {
        TransactionContext {
            block_context: self.clone(),
            tx_info: tx_info_creator.create_tx_info(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChainInfo {
    pub chain_id: ChainId,
    pub fee_token_addresses: FeeTokenAddresses,
}

impl ChainInfo {
    // TODO(Gilad): since fee_type comes from TransactionInfo, we can move this method into
    // TransactionContext, which has both the chain_info (through BlockContext) and the tx_info.
    // That is, add to BlockContext with the signature `pub fn fee_token_address(&self)`.
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
