use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::transaction::{Calldata, Fee, InvokeTransaction, TransactionSignature};
use starknet_api::{calldata, patricia_key, stark_felt};

use super::account_transaction::AccountTransaction;
use super::transaction_types::TransactionType;
use crate::abi::abi_utils::selector_from_name;
use crate::execution::contract_class::ContractClassV0;
use crate::test_utils::{
    TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS,
    TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH, TEST_FAULTY_ACCOUNT_CONTRACT_PATH,
};
use crate::transaction::constants;
use crate::transaction::transactions::DeclareTransaction;

pub fn create_account_tx_for_validate_test(
    tx_type: TransactionType,
    scenario: u64,
    additional_data: Option<StarkFelt>,
) -> AccountTransaction {
    // The first felt of the signature is used to set the scenario. If the scenario is
    // `CALL_CONTRACT` the second felt is used to pass the contract address.
    let signature = TransactionSignature(vec![
        StarkFelt::from(scenario),
        // Assumes the default value of StarkFelt is 0.
        additional_data.unwrap_or_default(),
    ]);

    match tx_type {
        TransactionType::Declare => {
            let contract_class =
                ContractClassV0::from_file(TEST_FAULTY_ACCOUNT_CONTRACT_PATH).into();
            let declare_tx = crate::test_utils::declare_tx(
                TEST_ACCOUNT_CONTRACT_CLASS_HASH,
                ContractAddress(patricia_key!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
                Fee(0),
                Some(signature),
            );

            AccountTransaction::Declare(
                DeclareTransaction::new(
                    starknet_api::transaction::DeclareTransaction::V1(declare_tx),
                    contract_class,
                )
                .unwrap(),
            )
        }
        TransactionType::DeployAccount => {
            let deploy_account_tx = crate::test_utils::deploy_account_tx(
                TEST_FAULTY_ACCOUNT_CONTRACT_CLASS_HASH,
                Fee(0),
                Some(calldata![stark_felt!(constants::FELT_FALSE)]),
                Some(signature),
            );
            AccountTransaction::DeployAccount(deploy_account_tx)
        }
        TransactionType::InvokeFunction => {
            let entry_point_selector = selector_from_name("foo");
            let execute_calldata = calldata![
                stark_felt!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS), // Contract address.
                entry_point_selector.0,                            // EP selector.
                stark_felt!(0_u8)                                  // Calldata length.
            ];
            let invoke_tx = crate::test_utils::invoke_tx(
                execute_calldata,
                ContractAddress(patricia_key!(TEST_FAULTY_ACCOUNT_CONTRACT_ADDRESS)),
                Fee(0),
                Some(signature),
            );
            AccountTransaction::Invoke(InvokeTransaction::V1(invoke_tx))
        }
        TransactionType::L1Handler => unimplemented!(),
    }
}
