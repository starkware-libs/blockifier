use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use strum::IntoEnumIterator;

use super::cached_state::create_contracts_mappings;
use crate::abi::abi_utils::get_fee_token_var_address;
use crate::context::ChainInfo;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::transaction::objects::FeeType;

/// Utility to fund an account.
pub fn fund_account(
    chain_info: &ChainInfo,
    account_address: ContractAddress,
    initial_balance: u128,
    state: &mut CachedState<DictStateReader>,
) {
    let storage_view = &mut state.state.storage_view;
    let balance_key = get_fee_token_var_address(account_address);
    for fee_type in FeeType::iter() {
        storage_view.insert(
            (chain_info.fee_token_address(&fee_type), balance_key),
            stark_felt!(initial_balance),
        );
    }
}

/// Initializes a state for testing:
/// * "Declares" a Cairo0 account and a Cairo0 ERC20 contract (class hash => class mapping set).
/// * "Deploys" two ERC20 contracts (address => class hash mapping set) at the fee token addresses
///   on the input block context.
/// * Makes the Cairo0 account privileged (minter on both tokens, funded in both tokens).
/// * "Declares" the input list of contracts.
/// * "Deploys" the requested number of instances of each input contract.
/// * Makes each input account contract privileged.
pub fn test_state(
    chain_info: &ChainInfo,
    initial_balances: u128,
    contract_instances: &[(FeatureContract, u8)],
) -> CachedState<DictStateReader> {
    // Set up the requested contracts.
    let (mut class_hash_to_class, mut address_to_class_hash) =
        create_contracts_mappings(contract_instances);

    // Declare and deploy account and ERC20 contracts.
    let erc20 = FeatureContract::ERC20;
    class_hash_to_class.insert(erc20.get_class_hash(), erc20.get_class());
    address_to_class_hash
        .insert(chain_info.fee_token_address(&FeeType::Eth), erc20.get_class_hash());
    address_to_class_hash
        .insert(chain_info.fee_token_address(&FeeType::Strk), erc20.get_class_hash());

    let mut state = CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        ..Default::default()
    });

    // fund the accounts.
    for (contract, n_instances) in contract_instances.iter() {
        for instance in 0..*n_instances {
            let instance_address = contract.get_instance_address(instance);
            match contract {
                FeatureContract::AccountWithLongValidate(_)
                | FeatureContract::AccountWithoutValidations(_)
                | FeatureContract::FaultyAccount(_) => {
                    fund_account(chain_info, instance_address, initial_balances, &mut state);
                }
                _ => (),
            }
        }
    }

    state
}
