use crate::test_utils::transfers_simulator::TransfersSimulator;

#[test]
pub fn transfers_flow_test() {
    let random_recipients = false;
    let disjoint_recipients = true;
    let n_chunks = 10;
    let mut transfers_simulator = TransfersSimulator::new(random_recipients, disjoint_recipients);
    for _ in 0..n_chunks {
        transfers_simulator.execute_chunk_of_transfers();
    }
}
