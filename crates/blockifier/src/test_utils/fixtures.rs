use rstest::fixture;
use starknet_api::transaction::{Fee, ResourceBoundsMapping};

use crate::block_context::BlockContext;
use crate::test_utils::{MAX_FEE, MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE};
use crate::transaction::test_utils::l1_resource_bounds;

#[cfg(test)]
#[fixture]
pub fn max_fee() -> Fee {
    Fee(MAX_FEE)
}

#[cfg(test)]
#[fixture]
pub fn max_resource_bounds() -> ResourceBoundsMapping {
    l1_resource_bounds(MAX_L1_GAS_AMOUNT, MAX_L1_GAS_PRICE)
}

#[cfg(test)]
#[fixture]
pub fn block_context() -> BlockContext {
    BlockContext::create_for_account_testing()
}
