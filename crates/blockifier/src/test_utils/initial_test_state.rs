use std::collections::HashMap;

use starknet_api::core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use strum::IntoEnumIterator;

use crate::abi::abi_utils::{get_fee_token_var_address, get_storage_var_address};
use crate::block_context::BlockContext;
use crate::state::cached_state::CachedState;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::dict_state_reader::DictStateReader;
use crate::test_utils::CairoVersion;
use crate::transaction::objects::FeeType;

// Number of instances of each contract to set by default in initial test state.
pub const N_INSTANCES: u8 = 2;

/// Sets up an initial state with all feature contracts "declared" (class hash => class mapping set)
/// and two instances of each contract "deployed" (address => class hash mapping set).
/// Also sets the two fee token address to the correct ERC20 class hash, and performs some initial
/// setup of the token contracts.
/// Takes the state from `full_unfunded_test_state` and sets a non-zero fee token balance for each
/// account contract.
fn full_test_state_aux(
    fee_token_address: ContractAddress,
    deprecated_fee_token_address: ContractAddress,
    initial_balance: u128,
) -> CachedState<DictStateReader> {
    let mut class_hash_to_class = HashMap::new();
    let mut address_to_class_hash = HashMap::new();
    let mut storage_view = HashMap::new();

    // Declare and deploy instances of all contracts.
    for version in CairoVersion::iter() {
        for mut contract in FeatureContract::iter() {
            // As some variants don't have cairo versions, use `match` to handle all variants
            // correctly.
            match contract {
                FeatureContract::AccountWithLongValidate(_)
                | FeatureContract::AccountWithoutValidations(_)
                | FeatureContract::Empty(_)
                | FeatureContract::FaultyAccount(_)
                | FeatureContract::TestContract(_) => {
                    contract.set_cairo_version(version);
                }
                FeatureContract::ERC20
                | FeatureContract::LegacyTestContract
                | FeatureContract::SecurityTests => (),
            }
            class_hash_to_class.insert(contract.get_class_hash(), contract.get_class());
            for instance_id in 0..N_INSTANCES {
                address_to_class_hash
                    .insert(contract.get_address(instance_id), contract.get_class_hash());
            }
        }
    }

    // Set the two fee token addresses to the ERC20 class hash.
    address_to_class_hash.insert(fee_token_address, FeatureContract::ERC20.get_class_hash());
    address_to_class_hash
        .insert(deprecated_fee_token_address, FeatureContract::ERC20.get_class_hash());

    // Set all accounts to be approved minters on both fee tokens.
    let minter_var_address = get_storage_var_address("permitted_minter", &[]);
    for version in CairoVersion::iter() {
        for fee_token in &[fee_token_address, deprecated_fee_token_address] {
            for account_instance in 0..N_INSTANCES {
                for account in &[
                    FeatureContract::AccountWithLongValidate(version),
                    FeatureContract::AccountWithoutValidations(version),
                ] {
                    storage_view.insert(
                        (*fee_token, minter_var_address),
                        *account.get_address(account_instance).0.key(),
                    );
                }
            }
        }
    }

    // Fund accounts.
    for version in CairoVersion::iter() {
        for fee_token in &[fee_token_address, deprecated_fee_token_address] {
            for account_instance in 0..N_INSTANCES {
                for account in &[
                    FeatureContract::AccountWithLongValidate(version),
                    FeatureContract::AccountWithoutValidations(version),
                ] {
                    let balance_key =
                        get_fee_token_var_address(&account.get_address(account_instance));
                    storage_view.insert((*fee_token, balance_key), stark_felt!(initial_balance));
                }
            }
        }
    }

    CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        storage_view,
        ..Default::default()
    })
}

/// Use to initialize a test state. If `fund` is true, also sets a non-zero fee token balance for
/// each account contract.
pub fn test_state(
    block_context: &BlockContext,
    initial_balances: u128,
) -> CachedState<DictStateReader> {
    let fee_token_address = block_context.fee_token_address(&FeeType::Strk);
    let deprecated_fee_token_address = block_context.fee_token_address(&FeeType::Eth);
    full_test_state_aux(fee_token_address, deprecated_fee_token_address, initial_balances)
}
