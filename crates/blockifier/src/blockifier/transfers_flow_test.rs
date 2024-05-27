use crate::test_utils::transfers_generator::{RecipientIteratorKind, TransfersGenerator};

#[test]
pub fn transfers_flow_test() {
    let mut transfers_generator =
        TransfersGenerator::new(RecipientIteratorKind::DisjointFromSenders);
    transfers_generator.execute_transfers_stream();
}
