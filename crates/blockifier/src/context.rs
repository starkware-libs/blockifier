use starknet_api::core::{ChainId, ContractAddress};

use crate::blockifier::block::BlockInfo;
use crate::bouncer::BouncerConfig;
use crate::transaction::objects::{
    FeeType, HasRelatedFeeType, TransactionInfo, TransactionInfoCreator,
};
use crate::versioned_constants::VersionedConstants;

/// Create via [`crate::blockifier::block::pre_process_block`] to ensure correctness.
#[derive(Clone, Debug)]
pub struct TransactionContext {
    pub block_context: BlockContext,
    pub tx_info: TransactionInfo,
}

impl TransactionContext {
    pub fn fee_token_address(&self) -> ContractAddress {
        self.block_context.chain_info.fee_token_address(&self.tx_info.fee_type())
    }
    pub fn is_sequencer_the_sender(&self) -> bool {
        self.tx_info.sender_address() == self.block_context.block_info.sequencer_address
    }
}

#[derive(Clone, Debug)]
pub struct BlockContext {
    // TODO(Yoni, 1/10/2024): consider making these fields public.
    pub(crate) block_info: BlockInfo,
    pub(crate) chain_info: ChainInfo,
    pub(crate) versioned_constants: VersionedConstants,
    pub(crate) bouncer_config: BouncerConfig,
}

impl BlockContext {
    pub fn new(
        block_info: BlockInfo,
        chain_info: ChainInfo,
        versioned_constants: VersionedConstants,
        bouncer_config: BouncerConfig,
    ) -> Self {
        BlockContext { block_info, chain_info, versioned_constants, bouncer_config }
    }

    pub fn block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    pub fn chain_info(&self) -> &ChainInfo {
        &self.chain_info
    }

    pub fn versioned_constants(&self) -> &VersionedConstants {
        &self.versioned_constants
    }

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

impl Default for ChainInfo {
    fn default() -> Self {
        ChainInfo {
            chain_id: ChainId::Other("0x0".to_string()),
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
