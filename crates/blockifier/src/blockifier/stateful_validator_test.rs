use assert_matches::assert_matches;
use starknet_api::transaction::Fee;

use crate::blockifier::stateful_validator::StatefulValidator;
use crate::bouncer::BouncerConfig;
use crate::context::BlockContext;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{CairoVersion, NonceManager, BALANCE};
use crate::transaction::test_utils::{
    create_account_tx_for_validate_test, FaultyAccountTxCreatorArgs, INVALID,
};
use crate::transaction::transaction_types::TransactionType;

#[test]
fn test_transaction_validator_skip_validate() {
    let block_context = BlockContext::create_for_testing();
    let faulty_account = FeatureContract::FaultyAccount(CairoVersion::Cairo1);
    let state = test_state(&block_context.chain_info, BALANCE, &[(faulty_account, 1)]);

    // Create a transaction that does not pass validations.
    let tx = create_account_tx_for_validate_test(
        &mut NonceManager::default(),
        FaultyAccountTxCreatorArgs {
            scenario: INVALID,
            tx_type: TransactionType::InvokeFunction,
            sender_address: faulty_account.get_instance_address(0),
            class_hash: faulty_account.get_class_hash(),
            max_fee: Fee(BALANCE),
            ..Default::default()
        },
    );

    let mut stateful_validator =
        StatefulValidator::create(state, block_context, BouncerConfig::max());
    // The transaction validations should be skipped and the function should return Ok.
    let result = stateful_validator.perform_validations(tx, true);
    assert_matches!(result, Ok(()));
}
