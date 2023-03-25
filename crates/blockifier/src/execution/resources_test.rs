use strum::IntoEnumIterator;

use crate::execution::resources::OS_RESOURCES;
use crate::transaction::objects::TransactionType;

#[test]
fn test_tx_types_have_resources_entry() {
    for tx_type in TransactionType::iter() {
        assert!(OS_RESOURCES.execute_txs_inner.get(&tx_type).is_some());
    }
}
