use crate::test_utils::transfers_simulator::TransfersSimulator;

#[test]
pub fn transfers_flow_test() {
    let n_chunks = 100;
    let mut transfers_simulator = TransfersSimulator::new();
    for _ in 0..n_chunks {
        transfers_simulator.execute_chunk_of_transfers();
    }
}
