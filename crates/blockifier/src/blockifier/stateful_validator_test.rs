use rstest::rstest;
use starknet_api::transaction::{Fee, TransactionVersion};

use crate::blockifier::stateful_validator::StatefulValidator;
use crate::bouncer::BouncerConfig;
use crate::context::BlockContext;
use crate::nonce;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::{fund_account, test_state};
use crate::test_utils::{CairoVersion, NonceManager, BALANCE};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::test_utils::{
    block_context, create_account_tx_for_validate_test, FaultyAccountTxCreatorArgs, VALID,
};
use crate::transaction::transaction_types::TransactionType;

#[rstest]
#[case::validate_version_1(TransactionType::InvokeFunction, false, TransactionVersion::ONE)]
#[case::validate_version_3(TransactionType::InvokeFunction, false, TransactionVersion::THREE)]
#[case::validate_declare_version_1(TransactionType::Declare, false, TransactionVersion::ONE)]
#[case::validate_declare_version_2(TransactionType::Declare, false, TransactionVersion::TWO)]
#[case::validate_declare_version_3(TransactionType::Declare, false, TransactionVersion::THREE)]
#[case::validate_deploy_version_1(TransactionType::DeployAccount, false, TransactionVersion::ONE)]
#[case::validate_deploy_version_3(TransactionType::DeployAccount, false, TransactionVersion::THREE)]
#[case::constructor_version_1(TransactionType::DeployAccount, true, TransactionVersion::ONE)]
#[case::constructor_version_3(TransactionType::DeployAccount, true, TransactionVersion::THREE)]
fn test_transaction_validator(
    #[case] tx_type: TransactionType,
    #[case] validate_constructor: bool,
    #[case] tx_version: TransactionVersion,
    block_context: BlockContext,
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let chain_info = &block_context.chain_info;

    // TODO(Arni, 1/5/2024): Add test for insufficient balance.
    let account_balance = BALANCE;
    let faulty_account = FeatureContract::FaultyAccount(cairo_version);
    let sender_address = faulty_account.get_instance_address(0);
    let class_hash = faulty_account.get_class_hash();

    let mut state = test_state(chain_info, account_balance, &[(faulty_account, 1)]);

    // TODO(Arni, 1/5/2024): Cover resource bounds in version 3 txs. Test the validator validate
    // enough "fee" in version 3 txs.
    let transaction_args = FaultyAccountTxCreatorArgs {
        tx_type,
        tx_version,
        sender_address,
        class_hash,
        validate_constructor,
        // TODO(Arni, 1/5/2024): Add test for insufficient max fee.
        max_fee: Fee(BALANCE),
        ..Default::default()
    };
    let nonce_manager = &mut NonceManager::default();

    // Positive flow.
    let tx = create_account_tx_for_validate_test(
        nonce_manager,
        FaultyAccountTxCreatorArgs { scenario: VALID, ..transaction_args },
    );
    if let AccountTransaction::DeployAccount(deploy_tx) = &tx {
        fund_account(chain_info, deploy_tx.contract_address, BALANCE, &mut state.state);
    }

    // Test the stateful validator.
    let mut stateful_validator = StatefulValidator::create(
        state,
        block_context,
        nonce!(0_u32),
        BouncerConfig::create_for_testing(),
    );

    let reuslt = stateful_validator.perform_validations(tx, None, None);
    assert!(reuslt.is_ok(), "Validation failed: {:?}", reuslt.unwrap_err());
}
