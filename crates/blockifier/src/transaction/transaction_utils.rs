use std::collections::HashMap;

use crate::abi::constants;
use crate::execution::entry_point::{CallInfo, ExecutionResources};
use crate::fee::gas_usage::calculate_tx_gas_usage;
use crate::fee::os_usage::get_additional_os_resources;
use crate::state::cached_state::TransactionalState;
use crate::state::state_api::StateReader;
use crate::transaction::errors::TransactionExecutionError;
use crate::transaction::objects::{ResourcesMapping, TransactionExecutionResult};
use crate::transaction::transaction_types::TransactionType;
use starknet_api::core::ContractAddress;
use crate::block_context::BlockContext;
use crate::state::cached_state::CachedState;
use starknet_api::transaction::Fee;

use starknet_api::core::{ClassHash, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::StorageKey;
use starknet_api::{patricia_key, stark_felt};

use crate::abi::abi_utils::get_storage_var_address;
use crate::execution::contract_class::ContractClassV0;
use crate::test_utils::{
    test_erc20_account_balance_key, DictStateReader,
    ACCOUNT_CONTRACT_PATH, BALANCE, ERC20_CONTRACT_PATH, TEST_ACCOUNT_CONTRACT_ADDRESS,
    TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH,
    TEST_ERC20_CONTRACT_CLASS_HASH, MAX_FEE, TEST_EMPTY_CONTRACT_CLASS_HASH,
};

const FEE_TRANSFER_N_STORAGE_CHANGES: u8 = 2; // Sender and sequencer balance update.
// Exclude the sequencer balance update, since it's charged once throughout the batch.
const FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE: u8 = FEE_TRANSFER_N_STORAGE_CHANGES - 1;

pub fn verify_no_calls_to_other_contracts(
    call_info: &CallInfo,
    entry_point_kind: String,
) -> TransactionExecutionResult<()> {
    let invoked_contract_address = call_info.call.storage_address;
    if call_info
        .into_iter()
        .any(|inner_call| inner_call.call.storage_address != invoked_contract_address)
    {
        return Err(TransactionExecutionError::UnauthorizedInnerCall { entry_point_kind });
    }

    Ok(())
}

/// Calculates the total resources needed to include the transaction in a StarkNet block as
/// most-recent (recent w.r.t. application on the given state).
/// I.e., L1 gas usage and Cairo VM execution resources.
pub fn calculate_tx_resources<S: StateReader>(
    execution_resources: ExecutionResources,
    call_infos: &[&CallInfo],
    tx_type: TransactionType,
    state: &mut TransactionalState<'_, S>,
    l1_handler_payload_size: Option<usize>,
) -> TransactionExecutionResult<ResourcesMapping> {
    let (n_storage_changes, n_modified_contracts, n_class_updates) =
        state.count_actual_state_changes();

    let mut l2_to_l1_payloads_length = vec![];
    for call_info in call_infos {
        l2_to_l1_payloads_length.extend(call_info.get_sorted_l2_to_l1_payloads_length()?);
    }

    let l1_gas_usage = calculate_tx_gas_usage(
        &l2_to_l1_payloads_length,
        n_modified_contracts,
        n_storage_changes + usize::from(FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE),
        l1_handler_payload_size,
        n_class_updates,
    );

    // Add additional Cairo resources needed for the OS to run the transaction.
    let total_vm_usage = &execution_resources.vm_resources
        + &get_additional_os_resources(execution_resources.syscall_counter, tx_type)?;
    let total_vm_usage = total_vm_usage.filter_unused_builtins();
    let mut tx_resources = HashMap::from([
        (constants::GAS_USAGE.to_string(), l1_gas_usage),
        (
            constants::N_STEPS_RESOURCE.to_string(),
            total_vm_usage.n_steps + total_vm_usage.n_memory_holes,
        ),
    ]);
    tx_resources.extend(total_vm_usage.builtin_instance_counter);

    Ok(ResourcesMapping(tx_resources))
}

pub fn create_account_tx_test_state(
    account_class_hash: &str,
    account_address: &str,
    account_path: &str,
    erc20_account_balance_key: StorageKey,
    initial_account_balance: u128,
) -> CachedState<DictStateReader> {
    let block_context = BlockContext::create_for_testing();

    let test_contract_class_hash = ClassHash(stark_felt!(TEST_CLASS_HASH));
    let test_account_class_hash = ClassHash(stark_felt!(account_class_hash));
    let test_erc20_class_hash = ClassHash(stark_felt!(TEST_ERC20_CONTRACT_CLASS_HASH));
    let class_hash_to_class = HashMap::from([
        (test_account_class_hash, ContractClassV0::from_file(account_path).into()),
        (test_contract_class_hash, ContractClassV0::from_file(TEST_CONTRACT_PATH).into()),
        (test_erc20_class_hash, ContractClassV0::from_file(ERC20_CONTRACT_PATH).into()),
    ]);
    let test_contract_address = ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS));
    // A random address that is unlikely to equal the result of the calculation of a contract
    // address.
    let test_account_address = ContractAddress(patricia_key!(account_address));
    let test_erc20_address = block_context.fee_token_address;
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_address, test_account_class_hash),
        (test_erc20_address, test_erc20_class_hash),
    ]);
    let minter_var_address = get_storage_var_address("permitted_minter", &[])
        .expect("Failed to get permitted_minter storage address.");
    let storage_view = HashMap::from([
        ((test_erc20_address, erc20_account_balance_key), stark_felt!(initial_account_balance)),
        // Give the account mint permission.
        ((test_erc20_address, minter_var_address), *test_account_address.0.key()),
    ]);
    CachedState::new(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
}


pub fn create_state_with_trivial_validation_account() -> CachedState<DictStateReader> {
    let account_balance = BALANCE;
    create_account_tx_test_state(
        TEST_ACCOUNT_CONTRACT_CLASS_HASH,
        TEST_ACCOUNT_CONTRACT_ADDRESS,
        ACCOUNT_CONTRACT_PATH,
        test_erc20_account_balance_key(),
        account_balance,
    )
}

use starknet_api::transaction::{
    DeclareTransactionV0V1, TransactionSignature,
};

pub fn declare_tx(
    class_hash: &str,
    sender_address: &str,
    signature: Option<TransactionSignature>,
) -> DeclareTransactionV0V1 {
    crate::test_utils::declare_tx(
        class_hash,
        ContractAddress(patricia_key!(sender_address)),
        Fee(MAX_FEE),
        signature,
    )
}

pub fn declare_tx_default() -> DeclareTransactionV0V1 {
    declare_tx(TEST_EMPTY_CONTRACT_CLASS_HASH, TEST_ACCOUNT_CONTRACT_ADDRESS, None)
}
