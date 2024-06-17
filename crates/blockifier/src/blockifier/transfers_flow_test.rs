use crate::test_utils::transfers_generator::TransfersGenerator;

#[test]
pub fn transfers_flow_test() {
    let mut transfers_generator = TransfersGenerator::new();
    transfers_generator.execute_chunk_of_transfers();
}
