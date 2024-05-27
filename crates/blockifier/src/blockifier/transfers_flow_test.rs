use crate::test_utils::transfers_simulator::{RecipientIteratorKind, TransfersSimulator};

#[test]
pub fn transfers_flow_test() {
    let n_chunks = 10;
    let mut transfers_simulator =
        TransfersSimulator::new(RecipientIteratorKind::DisjointFromSenders);
    for _ in 0..n_chunks {
        transfers_simulator.execute_chunk_of_transfers();
    }
}
