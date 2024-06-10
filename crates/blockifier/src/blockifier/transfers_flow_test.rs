use crate::test_utils::transfers_generator::{
    IndexIteratorType, TransfersGenerator, TransfersGeneratorConfig,
};

#[test]
pub fn transfers_flow_test() {
    let transfers_generator_config = TransfersGeneratorConfig {
        recipient_iterator_type: IndexIteratorType::Random(1),
        ..Default::default()
    };
    let mut transfers_generator = TransfersGenerator::new(transfers_generator_config);
    // Note: to make transactions in each chunk fully independent, make sure the number of accounts
    // is larger than the chunk size. Otherwise, the same account may be used in multiple
    // transactions in the same chunk.
    transfers_generator.execute_transfers();
}
