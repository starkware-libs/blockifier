use crate::test_utils::transfers_generator::{RecipientGeneratorType, TransfersGenerator};

#[test]
pub fn transfers_flow_test() {
    let mut transfers_generator =
        TransfersGenerator::new(RecipientGeneratorType::DisjointFromSenders);
    // Note: to make transactions in each chunk fully independent, make sure the number of accounts
    // is larger than the chunk size. Otherwise, the same account may be used in multiple
    // transactions in the same chunk.
    transfers_generator.execute_transfers_stream();
}
