use assert_matches::assert_matches;
use rstest::rstest;
use starknet_api::core::Nonce;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use crate::blockifier::stateful_validator::StatefulValidator;
use crate::bouncer::BouncerConfig;
use crate::context::BlockContext;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, NonceManager};
use crate::transaction::test_utils::{
    block_context, create_account_tx_for_validate_test, FaultyAccountTxCreatorArgs, VALID,
};
use crate::transaction::transaction_types::TransactionType;

#[rstest]
fn test_transaction_validator(
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let account_balance = 0;
    let faulty_account = FeatureContract::FaultyAccount(cairo_version);
    let sender_address = faulty_account.get_instance_address(0);
    let class_hash = faulty_account.get_class_hash();

    let state = test_state(&block_context.chain_info, account_balance, &[(faulty_account, 1)]);

    let tx_type = TransactionType::Declare;
    let validate_constructor = false;
    let default_args = FaultyAccountTxCreatorArgs {
        tx_type,
        sender_address,
        class_hash,
        validate_constructor,
        ..Default::default()
    };
    let nonce_manager = &mut NonceManager::default();

    let mut stateful_validator = StatefulValidator::create(
        state,
        block_context,
        Nonce(stark_felt!(1_u32)),
        BouncerConfig::default(),
    );

    // Positive flow.
    let tx = create_account_tx_for_validate_test(
        nonce_manager,
        FaultyAccountTxCreatorArgs { scenario: VALID, additional_data: None, ..default_args },
    );

    let result = stateful_validator.perform_validations(tx, None);
    assert_matches!(result, Ok(()));
}
