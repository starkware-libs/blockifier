use assert_matches::assert_matches;
use rstest::rstest;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::transaction::{Calldata, Fee, ResourceBoundsMapping, TransactionVersion};
use starknet_api::{patricia_key, stark_felt};
use starknet_crypto::FieldElement;

use crate::context::{BlockContext, ChainInfo};
use crate::fee::fee_checks::FeeCheckError;
use crate::invoke_tx_args;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{create_calldata, CairoVersion, BALANCE, MAX_L1_GAS_PRICE};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{FeeType, HasRelatedFeeType, TransactionInfoCreator};
use crate::transaction::test_utils::{
    account_invoke_tx, block_context, l1_resource_bounds, max_fee, max_resource_bounds,
    run_invoke_tx, TestInitData,
};
use crate::transaction::transactions::ExecutableTransaction;

fn init_data_by_version(chain_info: &ChainInfo, cairo_version: CairoVersion) -> TestInitData {
    let test_contract = FeatureContract::TestContract(cairo_version);
    let account_contract = FeatureContract::AccountWithoutValidations(cairo_version);
    let state = test_state(chain_info, BALANCE, &[(account_contract, 1), (test_contract, 1)]);
    TestInitData {
        state,
        account_address: account_contract.get_instance_address(0),
        contract_address: test_contract.get_instance_address(0),
        nonce_manager: Default::default(),
    }
}

fn calldata_for_write_and_transfer(
    test_contract_address: ContractAddress,
    storage_address: StarkFelt,
    storage_value: StarkFelt,
    recipient: StarkFelt,
    transfer_amount: StarkFelt,
    fee_token_address: ContractAddress,
) -> Calldata {
    create_calldata(
        test_contract_address,
        "test_write_and_transfer",
        &[
            storage_address,            // Calldata: storage address.
            storage_value,              // Calldata: storage value.
            recipient,                  // Calldata: to.
            transfer_amount,            // Calldata: amount.
            *fee_token_address.0.key(), // Calldata: fee token address.
        ],
    )
}

/// Tests that when a transaction drains an account's balance before fee transfer, the execution is
/// reverted.
#[rstest]
#[case(TransactionVersion::ONE, FeeType::Eth)]
#[case(TransactionVersion::THREE, FeeType::Strk)]
fn test_revert_on_overdraft(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    #[case] fee_type: FeeType,
    #[values(CairoVersion::Cairo0)] cairo_version: CairoVersion,
) {
    let chain_info = &block_context.chain_info;
    let fee_token_address = chain_info.fee_token_addresses.get_by_fee_type(&fee_type);
    // An address to be written into to observe state changes.
    let storage_address = stark_felt!(10_u8);
    let storage_key = StorageKey::try_from(storage_address).unwrap();
    // Final storage value expected in the address at the end of this test.
    let expected_final_value = stark_felt!(77_u8);
    // An address to be used as recipient of a transfer.
    let recipient = stark_felt!(7_u8);
    let recipient_address = ContractAddress(patricia_key!(recipient));
    // Amount expected to be transferred successfully.
    let final_received_amount = stark_felt!(80_u8);

    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        init_data_by_version(chain_info, cairo_version);

    // Verify the contract's storage key initial value is empty.
    assert_eq!(state.get_storage_at(contract_address, storage_key).unwrap(), stark_felt!(0_u8));

    // Approve the test contract to transfer funds.
    let approve_calldata = create_calldata(
        fee_token_address,
        "approve",
        &[
            *contract_address.0.key(), // Calldata: to.
            stark_felt!(BALANCE),
            stark_felt!(0_u8),
        ],
    );

    let approve_tx: AccountTransaction = account_invoke_tx(invoke_tx_args! {
        max_fee,
        sender_address: account_address,
        calldata: approve_calldata,
        version,
        resource_bounds: max_resource_bounds.clone(),
        nonce: nonce_manager.next(account_address),
    });
    let tx_info = approve_tx.create_tx_info();
    let approval_execution_info =
        approve_tx.execute(&mut state, &block_context, true, true).unwrap();
    assert!(!approval_execution_info.is_reverted());

    // Transfer a valid amount of funds to compute the cost of a successful
    // `test_write_and_transfer` operation. This operation should succeed.
    let execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: calldata_for_write_and_transfer(
                contract_address,
                storage_address,
                expected_final_value,
                recipient,
                final_received_amount,
                fee_token_address
            ),
            version,
            resource_bounds: max_resource_bounds.clone(),
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();

    assert!(!execution_info.is_reverted());
    let transfer_tx_fee = execution_info.actual_fee;

    // Check the current balance, before next transaction.
    let (balance, _) = state
        .get_fee_token_balance(account_address, chain_info.fee_token_address(&tx_info.fee_type()))
        .unwrap();

    // Attempt to transfer the entire balance, such that no funds remain to pay transaction fee.
    // This operation should revert.
    let execution_info = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            sender_address: account_address,
            calldata: calldata_for_write_and_transfer(
                contract_address,
                storage_address,
                stark_felt!(0_u8),
                recipient,
                balance,
                fee_token_address
            ),
            version,
            resource_bounds: max_resource_bounds,
            nonce: nonce_manager.next(account_address),
        },
    )
    .unwrap();

    // Compute the expected balance after the reverted write+transfer (tx fee should be charged).
    let expected_new_balance: StarkFelt =
        StarkFelt::from(FieldElement::from(balance) - FieldElement::from(transfer_tx_fee.0));

    // Verify the execution was reverted (including nonce bump) with the correct error.
    assert!(execution_info.is_reverted());
    assert!(execution_info.revert_error.unwrap().starts_with("Insufficient fee token balance"));
    assert_eq!(state.get_nonce_at(account_address).unwrap(), nonce_manager.next(account_address));

    // Verify the storage key/value were not updated in the last tx.
    assert_eq!(state.get_storage_at(contract_address, storage_key).unwrap(), expected_final_value);

    // Verify balances of both sender and recipient are as expected.
    assert_eq!(
        state
            .get_fee_token_balance(
                account_address,
                chain_info.fee_token_address(&tx_info.fee_type()),
            )
            .unwrap(),
        (expected_new_balance, stark_felt!(0_u8))
    );
    assert_eq!(
        state
            .get_fee_token_balance(
                recipient_address,
                chain_info.fee_token_address(&tx_info.fee_type())
            )
            .unwrap(),
        (final_received_amount, stark_felt!(0_u8))
    );
}

/// Tests that when a transaction requires more resources than what the sender bounds allow, the
/// execution is reverted; in the non-revertible case, checks for the correct error.
// TODO(Aner, 21/01/24) modify for 4844 (taking blob_gas into account).
#[rstest]
#[case(TransactionVersion::ZERO, "", false)]
#[case(TransactionVersion::ONE, "Insufficient max fee", true)]
#[case(TransactionVersion::THREE, "Insufficient max L1 gas", true)]
fn test_revert_on_resource_overuse(
    max_fee: Fee,
    max_resource_bounds: ResourceBoundsMapping,
    block_context: BlockContext,
    #[case] version: TransactionVersion,
    #[case] expected_error_prefix: &str,
    #[case] is_revertible: bool,
    #[values(CairoVersion::Cairo0)] cairo_version: CairoVersion,
) {
    let TestInitData { mut state, account_address, contract_address, mut nonce_manager } =
        init_data_by_version(&block_context.chain_info, cairo_version);

    let n_writes = 5_u8;
    let base_args = invoke_tx_args! { sender_address: account_address, version };

    // Utility function to generate calldata for the `write_a_lot` function.
    // Change the written value each call to keep cost high.
    let mut value_to_write = 1_u8;
    let mut write_a_lot_calldata = || {
        value_to_write += 1;
        create_calldata(
            contract_address,
            "write_a_lot",
            &[stark_felt!(n_writes), stark_felt!(value_to_write)],
        )
    };

    // Run a "heavy" transaction and measure the resources used.
    // In this context, "heavy" means: a substantial fraction of the cost is not cairo steps.
    // We need this kind of invocation, to be able to test the specific scenario: the resource
    // bounds must be enough to allow completion of the transaction, and yet must still fail
    // post-execution bounds check.
    let execution_info_measure = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee,
            resource_bounds: max_resource_bounds,
            nonce: nonce_manager.next(account_address),
            calldata: write_a_lot_calldata(),
            ..base_args.clone()
        },
    )
    .unwrap();
    assert_eq!(execution_info_measure.revert_error, None);
    let actual_fee = execution_info_measure.actual_fee;
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion works.
    let actual_gas_usage: u64 = execution_info_measure
        .actual_resources
        .to_gas_vector(&block_context.versioned_constants, block_context.block_info.use_kzg_da)
        .unwrap()
        .l1_gas
        .try_into()
        .expect("Failed to convert u128 to u64.");

    // Run the same function, with a different written value (to keep cost high), with the actual
    // resources used as upper bounds. Make sure execution does not revert.
    let execution_info_tight = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: actual_fee,
            resource_bounds: l1_resource_bounds(actual_gas_usage, MAX_L1_GAS_PRICE),
            nonce: nonce_manager.next(account_address),
            calldata: write_a_lot_calldata(),
            ..base_args.clone()
        },
    )
    .unwrap();
    assert_eq!(execution_info_tight.revert_error, None);
    assert_eq!(execution_info_tight.actual_fee, actual_fee);
    assert_eq!(execution_info_tight.actual_resources, execution_info_measure.actual_resources);

    // Re-run the same function with max bounds slightly below the actual usage, and verify it's
    // reverted.
    let low_max_fee = Fee(execution_info_measure.actual_fee.0 - 1);
    let execution_info_result = run_invoke_tx(
        &mut state,
        &block_context,
        invoke_tx_args! {
            max_fee: low_max_fee,
            resource_bounds: l1_resource_bounds(actual_gas_usage - 1, MAX_L1_GAS_PRICE),
            nonce: nonce_manager.next(account_address),
            calldata: write_a_lot_calldata(),
            ..base_args
        },
    );

    // Assert the transaction was reverted with the correct error.
    if is_revertible {
        assert!(
            execution_info_result.unwrap().revert_error.unwrap().starts_with(expected_error_prefix)
        );
    } else {
        assert_matches!(
            execution_info_result.unwrap_err(),
            TransactionExecutionError::FeeCheckError(
                FeeCheckError::MaxFeeExceeded { max_fee, actual_fee: fee_in_error }
            )
            if (max_fee, fee_in_error) == (low_max_fee, actual_fee)
        );
    }
}
