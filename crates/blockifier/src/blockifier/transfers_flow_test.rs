use crate::test_utils::transfers_generator::{RecipientIteratorKind, TransfersGenerator};

#[test]
pub fn transfers_flow_test() {
    let n_chunks = 10;
    let mut transfers_generator =
        TransfersGenerator::new(RecipientIteratorKind::DisjointFromSenders);
    for _ in 0..n_chunks {
        transfers_generator.execute_chunk_of_transfers();
    }
}
