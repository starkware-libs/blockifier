use starknet_api::transaction::Fee;

use crate::block_context::BlockContext;

pub fn calculate_tx_fee(_block_context: &BlockContext) -> Fee {
    Fee(1)
}
