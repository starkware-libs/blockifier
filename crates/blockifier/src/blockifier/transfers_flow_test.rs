use crate::test_utils::transfers_generator::TransfersGenerator;

#[test]
pub fn transfers_flow_test() {
    let concurrency_mode = true;
    let mut transfers_generator = TransfersGenerator::new(concurrency_mode);
    transfers_generator.execute_chunk_of_transfers();
}
