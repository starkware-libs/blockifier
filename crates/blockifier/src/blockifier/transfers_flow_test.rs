use crate::test_utils::transfers_generator::{
    RecipientGeneratorType, TransfersGenerator, TransfersGeneratorConfig,
};

#[test]
pub fn transfers_flow_test() {
    let transfers_generator_config = TransfersGeneratorConfig {
        recipient_generator_type: RecipientGeneratorType::DisjointFromSenders,
        ..Default::default()
    };
    assert!(
        usize::from(transfers_generator_config.n_accounts)
            >= transfers_generator_config.concurrency_config.chunk_size,
        "The number of accounts must be at least the chunk size. Otherwise, the same account may \
         be used in multiple transactions in the same chunk, making the chunk not fully \
         independent."
    );
    let mut transfers_generator = TransfersGenerator::new(transfers_generator_config);
    transfers_generator.execute_transfers();
}
