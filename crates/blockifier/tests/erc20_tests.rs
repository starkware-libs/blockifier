// run with:
// cargo test --test erc20_tests --features testing
use blockifier::execution::sierra_utils::{
    contract_address_to_felt, native_felt_to_stark_felt, stark_felt_to_native_felt,
};
use blockifier::test_utils::*;
use starknet_api::hash::StarkFelt;
use starknet_types_core::felt::Felt;

pub const TOTAL_SUPPLY: u128 = 10_000_000_000_000_000_000_000u128;
pub const BALANCE_TO_TRANSFER: u128 = 10u128;
pub const BALANCE_AFTER_TRANSFER: u128 = TOTAL_SUPPLY - BALANCE_TO_TRANSFER;
pub const U256_SUB_OVERFLOW: &str = "Native execution error: u256_sub Overflow";
pub const CALLER_IS_NOT_THE_OWNER: &str = "Native execution error: Caller is not the owner";

pub const NAME: &str = "Native";
pub const SYMBOL: &str = "MTK";
pub const DECIMALS: u128 = 18;

#[test]
fn should_deploy() {
    let (_contract_address, _state) = prepare_erc20_deploy_test_state();
}

#[cfg(test)]
mod read_only_methods_tests {
    use super::*;

    #[test]
    fn test_total_supply() {
        let mut context = TestContext::new();

        let result = context.call_entry_point("total_supply", vec![]);

        assert_eq!(result, vec![Felt::from(TOTAL_SUPPLY), Felt::from(0u8)]);
    }

    #[test]
    fn test_balance_of() {
        let address = native_felt_to_stark_felt(contract_address_to_felt(Signers::Alice.into()));

        let mut context = TestContext::new();
        let result = context.call_entry_point("balance_of", vec![address]);

        assert_eq!(result, vec![Felt::from(TOTAL_SUPPLY), Felt::from(0u8)]);
    }
}

mod transfer_tests {
    use super::*;

    #[test]
    fn test_transfer_normal_scenario() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;

        let total_supply = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER));
        let balance_after_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_AFTER_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "transfer",
                vec![address_to.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(balance_after_transfer), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![stark_felt_to_native_felt(balance_to_transfer), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;

        let total_supply = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY + 1));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            &context
                .call_entry_point_raw(
                    "transfer",
                    vec![address_to.into(), balance_to_transfer, StarkFelt::from(0u128)],
                )
                .unwrap_err(),
            U256_SUB_OVERFLOW,
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_transfer_emits_event() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;

        let total_supply = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER));
        let balance_after_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_AFTER_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "transfer",
                vec![address_to.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(balance_after_transfer), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![stark_felt_to_native_felt(balance_to_transfer), Felt::from(0u128)]
        );

        let event = context.get_event(0).unwrap();
        let event = (event.keys[1], event.keys[2], event.data[0]);

        assert_eq!(
            event,
            (
                address_from.into(),
                address_to.into(),
                stark_felt_to_native_felt(balance_to_transfer),
            )
        );
    }
}

#[cfg(test)]
mod allowance_tests {
    use super::*;

    #[test]
    fn test_approve() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;

        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("allowance", vec![address_from.into(), address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "approve",
                vec![address_to.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        assert_eq!(
            context.call_entry_point("allowance", vec![address_from.into(), address_to.into()]),
            vec![stark_felt_to_native_felt(balance_to_transfer), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_approve_emits_event() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;

        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("allowance", vec![address_from.into(), address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "approve",
                vec![address_to.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        assert_eq!(
            context.call_entry_point("allowance", vec![address_from.into(), address_to.into()]),
            vec![stark_felt_to_native_felt(balance_to_transfer), Felt::from(0u128)]
        );

        let event = context.get_event(0).unwrap();
        let event = (event.keys[1], event.keys[2], event.data[0]);

        assert_eq!(
            event,
            (
                address_from.into(),
                address_to.into(),
                stark_felt_to_native_felt(balance_to_transfer),
            )
        );
    }
}

#[cfg(test)]
mod transfer_from_tests {
    use super::*;

    #[test]
    fn test_transfer_from() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;
        let address_spender = Signers::Charlie;

        let total_supply = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER));
        let balance_after_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_AFTER_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "approve",
                vec![address_spender.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        let mut context = context.with_caller(address_spender.into());

        assert_eq!(
            context.call_entry_point(
                "transfer_from",
                vec![
                    address_from.into(),
                    address_to.into(),
                    balance_to_transfer,
                    StarkFelt::from(0u128)
                ],
            ),
            vec![Felt::from(true)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(balance_after_transfer), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![stark_felt_to_native_felt(balance_to_transfer), Felt::from(0u128)]
        );
    }

    #[test]
    fn transfer_from_insufficient_allowance() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;
        let address_spender = Signers::Charlie;

        let total_supply = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "approve",
                vec![address_spender.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        let mut context = context.with_caller(address_spender.into());

        assert_eq!(
            &context
                .call_entry_point_raw(
                    "transfer_from",
                    vec![
                        address_from.into(),
                        address_to.into(),
                        native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER + 1)),
                        StarkFelt::from(0u128)
                    ],
                )
                .unwrap_err(),
            "Native execution error: u256_sub Overflow",
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_transfer_from_insufficient_balance() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;
        let address_spender = Signers::Charlie;

        let total_supply = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY + 1));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "approve",
                vec![address_spender.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        let mut context = context.with_caller(address_spender.into());

        assert_eq!(
            &context
                .call_entry_point_raw(
                    "transfer_from",
                    vec![
                        address_from.into(),
                        address_to.into(),
                        balance_to_transfer,
                        StarkFelt::from(0u128)
                    ],
                )
                .unwrap_err(),
            U256_SUB_OVERFLOW,
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_transfer_from_emits_event() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;
        let address_spender = Signers::Charlie;

        let total_supply = native_felt_to_stark_felt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = native_felt_to_stark_felt(Felt::from(BALANCE_TO_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![stark_felt_to_native_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "approve",
                vec![address_spender.into(), balance_to_transfer, StarkFelt::from(0u128)],
            ),
            vec![Felt::from(true)]
        );

        // Approve event
        let event = context.get_event(0).unwrap();
        let event = (event.keys[1], event.keys[2], event.data[0]);

        assert_eq!(
            event,
            (
                address_from.into(),
                address_spender.into(),
                stark_felt_to_native_felt(balance_to_transfer),
            )
        );

        let mut context = context.with_caller(address_spender.into());

        assert_eq!(
            context.call_entry_point(
                "transfer_from",
                vec![
                    address_from.into(),
                    address_to.into(),
                    balance_to_transfer,
                    StarkFelt::from(0u128)
                ],
            ),
            vec![Felt::from(true)]
        );

        // Transfer event
        let event = context.get_event(2).unwrap();
        let event = (event.keys[1], event.keys[2], event.data[0]);

        assert_eq!(
            event,
            (
                address_from.into(),
                address_to.into(),
                stark_felt_to_native_felt(balance_to_transfer),
            )
        );
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    #[test]
    fn test_name() {
        let mut context = TestContext::new();
        let result = context.call_entry_point("name", vec![]);

        assert_eq!(
            result,
            vec![Felt::from(0), Felt::from_bytes_be_slice(NAME.as_bytes()), Felt::from(NAME.len())]
        );
    }

    #[test]
    fn test_symbol() {
        let mut context = TestContext::new();
        let result = context.call_entry_point("symbol", vec![]);

        assert_eq!(
            result,
            vec![
                Felt::from(0),
                Felt::from_bytes_be_slice(SYMBOL.as_bytes()),
                Felt::from(SYMBOL.len())
            ]
        );
    }

    #[test]
    fn test_decimals() {
        let mut context = TestContext::new();
        let result = context.call_entry_point("decimals", vec![]);

        assert_eq!(result, vec![Felt::from(DECIMALS)]);
    }
}

#[cfg(test)]
pub mod mintable_tests {
    use super::*;

    #[test]
    fn test_mint_normal_scenario() {
        let address_to_mint_to = Signers::Bob;

        let mut context = TestContext::new().with_caller(Signers::Alice.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to_mint_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "mint",
                vec![
                    address_to_mint_to.into(),
                    StarkFelt::from(BALANCE_TO_TRANSFER),
                    StarkFelt::from(0u128),
                ],
            ),
            vec![]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to_mint_to.into()]),
            vec![Felt::from(BALANCE_TO_TRANSFER), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("total_supply", vec![]),
            vec![Felt::from(TOTAL_SUPPLY + BALANCE_TO_TRANSFER), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_not_owner_cannot_mint_tokens() {
        let address_to_mint_to = Signers::Charlie;
        let address_of_minter = Signers::Bob;

        let mut context = TestContext::new().with_caller(address_of_minter.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to_mint_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            &context
                .call_entry_point_raw(
                    "mint",
                    vec![
                        address_to_mint_to.into(),
                        StarkFelt::from(BALANCE_TO_TRANSFER),
                        StarkFelt::from(0u128)
                    ]
                )
                .unwrap_err(),
            CALLER_IS_NOT_THE_OWNER,
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to_mint_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("total_supply", vec![]),
            vec![Felt::from(TOTAL_SUPPLY), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_mint_emits_event() {
        let address_to_mint_to = Signers::Bob;
        let owner = Signers::Alice;

        let mut context = TestContext::new().with_caller(owner.into());

        assert_eq!(
            context.call_entry_point(
                "mint",
                vec![
                    address_to_mint_to.into(),
                    StarkFelt::from(BALANCE_TO_TRANSFER),
                    StarkFelt::from(0u128),
                ],
            ),
            vec![]
        );

        let event = context.get_event(0).unwrap();

        let event = (event.keys[1], event.keys[2], event.data[0]);

        assert_eq!(
            event,
            (
                Felt::from_hex("0x0").unwrap(),
                address_to_mint_to.into(),
                Felt::from(BALANCE_TO_TRANSFER)
            )
        );
    }
}

#[cfg(test)]
pub mod burnable_tests {
    use super::*;

    #[test]
    fn test_burnable_normal_scenario() {
        let address_to_burn_from = Signers::Alice;

        let mut context = TestContext::new().with_caller(address_to_burn_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to_burn_from.into()]),
            vec![Felt::from(TOTAL_SUPPLY), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point(
                "burn",
                vec![StarkFelt::from(BALANCE_TO_TRANSFER), StarkFelt::from(0u128)],
            ),
            vec![]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to_burn_from.into()]),
            vec![Felt::from(TOTAL_SUPPLY - BALANCE_TO_TRANSFER), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("total_supply", vec![]),
            vec![Felt::from(TOTAL_SUPPLY - BALANCE_TO_TRANSFER), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_cannot_burn_insufficient_amount() {
        let mut context = TestContext::new();

        assert_eq!(
            &context
                .call_entry_point_raw(
                    "burn",
                    vec![StarkFelt::from(TOTAL_SUPPLY + 1), StarkFelt::from(0u128)]
                )
                .unwrap_err(),
            U256_SUB_OVERFLOW,
        );

        assert_eq!(
            context.call_entry_point("total_supply", vec![]),
            vec![Felt::from(TOTAL_SUPPLY), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_burn_emits_event() {
        let address_to_burn_from = Signers::Alice;

        let mut context = TestContext::new().with_caller(address_to_burn_from.into());

        assert_eq!(
            context.call_entry_point(
                "burn",
                vec![StarkFelt::from(BALANCE_TO_TRANSFER), StarkFelt::from(0u128)],
            ),
            vec![]
        );

        let event = context.get_event(0).unwrap();

        let event = (event.keys[1], event.keys[2], event.data[0]);

        assert_eq!(
            event,
            (
                address_to_burn_from.into(),
                Felt::from_hex("0x0").unwrap(),
                Felt::from(BALANCE_TO_TRANSFER)
            )
        );
    }
}

#[cfg(test)]
pub mod ownable_tests {
    use super::*;

    #[test]
    fn test_transfer_ownership() {
        let current_owner = Signers::Alice;
        let new_owner = Signers::Bob;

        let mut context = TestContext::new().with_caller(Signers::Alice.into());

        assert_eq!(context.call_entry_point("owner", vec![]), vec![current_owner.into()]);

        assert_eq!(context.call_entry_point("transfer_ownership", vec![new_owner.into()]), vec![]);

        assert_eq!(context.call_entry_point("owner", vec![]), vec![new_owner.into()]);
    }

    #[test]
    fn test_not_owner_cannot_transfer_ownership() {
        let current_owner = Signers::Alice;
        let new_owner = Signers::Bob;

        let mut context = TestContext::new().with_caller(Signers::Charlie.into());

        assert_eq!(context.call_entry_point("owner", vec![]), vec![current_owner.into()]);

        assert_eq!(
            &context
                .call_entry_point_raw("transfer_ownership", vec![new_owner.into()])
                .unwrap_err(),
            CALLER_IS_NOT_THE_OWNER,
        );

        assert_eq!(context.call_entry_point("owner", vec![]), vec![current_owner.into()]);
    }

    #[test]
    fn test_transfer_ownership_emits_event() {
        let current_owner = Signers::Alice;
        let new_owner = Signers::Bob;

        let mut context = TestContext::new().with_caller(current_owner.into());

        assert_eq!(context.call_entry_point("transfer_ownership", vec![new_owner.into()]), vec![]);

        let event = context.get_event(0).unwrap();

        let event = (event.keys[1], event.keys[2]);

        assert_eq!(event, (current_owner.into(), new_owner.into()));
    }
}

#[cfg(test)]
mod pausable_tests {
    use super::*;

    #[test]
    fn test_pause_unpause() {
        let owner = Signers::Alice;

        let mut context = TestContext::new().with_caller(owner.into());

        assert_eq!(context.call_entry_point("is_paused", vec![]), vec![Felt::from(false)]);

        assert_eq!(context.call_entry_point("pause", vec![]), vec![]);

        assert_eq!(context.call_entry_point("is_paused", vec![]), vec![Felt::from(true)]);

        assert_eq!(context.call_entry_point("unpause", vec![]), vec![]);
    }

    #[test]
    fn test_pause_unpause_emits_event() {
        let owner = Signers::Alice;

        let mut context = TestContext::new().with_caller(owner.into());

        assert_eq!(context.call_entry_point("pause", vec![]), vec![]);

        let event = context.get_event(0).unwrap();

        let event = event.data[0];

        assert_eq!(event, owner.into());

        assert_eq!(context.call_entry_point("unpause", vec![]), vec![]);

        let event = context.get_event(1).unwrap();

        let event = event.data[0];

        assert_eq!(event, owner.into());
    }
}

#[cfg(test)]
mod upgradable_tests {
    use super::*;

    #[test]
    fn test_upgrade_emits_event() {
        let owner = Signers::Alice;

        let code_hash = Felt::from_hex(TEST_EMPTY_CONTRACT_CLASS_HASH).unwrap();

        let mut context = TestContext::new().with_caller(owner.into());

        assert_eq!(
            context.call_entry_point("upgrade", vec![native_felt_to_stark_felt(code_hash)]),
            vec![]
        );

        let event = context.get_event(0).unwrap();

        let event = event.data[0];

        assert_eq!(event, code_hash);
    }
}
