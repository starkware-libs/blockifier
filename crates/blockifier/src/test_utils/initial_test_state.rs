use std::collections::HashMap;

use starknet_api::core::ContractAddress;
use starknet_api::felt;
use strum::IntoEnumIterator;

use crate::abi::abi_utils::get_fee_token_var_address;
use crate::context::ChainInfo;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::CairoVersion;
use crate::transaction::objects::FeeType;

/// Utility to fund an account.
pub fn fund_account(
    chain_info: &ChainInfo,
    account_address: ContractAddress,
    initial_balance: u128,
    state_reader: &mut DictStateReader,
) {
    let storage_view = &mut state_reader.storage_view;
    let balance_key = get_fee_token_var_address(account_address);
    for fee_type in FeeType::iter() {
        storage_view
            .insert((chain_info.fee_token_address(&fee_type), balance_key), felt!(initial_balance));
    }
}

/// Initializes a state reader for testing:
/// * "Declares" a Cairo0 account and a Cairo0 ERC20 contract (class hash => class mapping set).
/// * "Deploys" two ERC20 contracts (address => class hash mapping set) at the fee token addresses
///   on the input block context.
/// * Makes the Cairo0 account privileged (minter on both tokens, funded in both tokens).
/// * "Declares" the input list of contracts.
/// * "Deploys" the requested number of instances of each input contract.
/// * Makes each input account contract privileged.
pub fn test_state_inner(
    chain_info: &ChainInfo,
    initial_balances: u128,
    contract_instances: &[(FeatureContract, u16)],
    erc20_contract_version: CairoVersion,
) -> CachedState<DictStateReader> {
    let mut class_hash_to_class = HashMap::new();
    let mut address_to_class_hash = HashMap::new();

    // Declare and deploy account and ERC20 contracts.
    let erc20 = FeatureContract::ERC20(erc20_contract_version);
    class_hash_to_class.insert(erc20.get_class_hash(), erc20.get_class());
    address_to_class_hash
        .insert(chain_info.fee_token_address(&FeeType::Eth), erc20.get_class_hash());
    address_to_class_hash
        .insert(chain_info.fee_token_address(&FeeType::Strk), erc20.get_class_hash());

    // Set up the rest of the requested contracts.
    for (contract, n_instances) in contract_instances.iter() {
        let class_hash = contract.get_class_hash();
        class_hash_to_class.insert(class_hash, contract.get_class());
        for instance in 0..*n_instances {
            let instance_address = contract.get_instance_address(instance);
            address_to_class_hash.insert(instance_address, class_hash);
        }
    }

    let mut state_reader =
        DictStateReader { address_to_class_hash, class_hash_to_class, ..Default::default() };

    // fund the accounts.
    for (contract, n_instances) in contract_instances.iter() {
        for instance in 0..*n_instances {
            let instance_address = contract.get_instance_address(instance);
            match contract {
                FeatureContract::AccountWithLongValidate(_)
                | FeatureContract::AccountWithoutValidations(_)
                | FeatureContract::FaultyAccount(_) => {
                    fund_account(chain_info, instance_address, initial_balances, &mut state_reader);
                }
                _ => (),
            }
        }
    }

    CachedState::from(state_reader)
}

pub fn test_state(
    chain_info: &ChainInfo,
    initial_balances: u128,
    contract_instances: &[(FeatureContract, u16)],
) -> CachedState<DictStateReader> {
    test_state_inner(chain_info, initial_balances, contract_instances, CairoVersion::Cairo0)
}
