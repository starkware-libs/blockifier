// run with:
// cargo test --test erc20_tests --features testing
use blockifier::execution::sierra_utils::{
    contract_address_to_felt, felt_to_starkfelt, starkfelt_to_felt,
};
use blockifier::test_utils::*;
use starknet_api::hash::StarkFelt;
use starknet_types_core::felt::Felt;

pub const TOTAL_SUPPLY: u128 = 10_000_000_000_000_000_000_000u128;
pub const BALANCE_TO_TRANSFER: u128 = 10u128;
pub const BALANCE_AFTER_TRANSFER: u128 = 9_999_999_999_999_999_999_990u128;
pub const U256_UNDERFLOW: &str = "0x753235365f737562204f766572666c6f77";
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
        let address = felt_to_starkfelt(contract_address_to_felt(Signers::Alice.into()));

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

        let total_supply = felt_to_starkfelt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = felt_to_starkfelt(Felt::from(BALANCE_TO_TRANSFER));
        let balance_after_transfer = felt_to_starkfelt(Felt::from(BALANCE_AFTER_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
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
            vec![starkfelt_to_felt(balance_after_transfer), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![starkfelt_to_felt(balance_to_transfer), Felt::from(0u128)]
        );
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;

        let total_supply = felt_to_starkfelt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = felt_to_starkfelt(Felt::from(TOTAL_SUPPLY + 1));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
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
            vec![Felt::from_hex(U256_UNDERFLOW).unwrap()]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
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

        let balance_to_transfer = felt_to_starkfelt(Felt::from(BALANCE_TO_TRANSFER));

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
            vec![starkfelt_to_felt(balance_to_transfer), Felt::from(0u128)]
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

        let total_supply = felt_to_starkfelt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = felt_to_starkfelt(Felt::from(BALANCE_TO_TRANSFER));
        let balance_after_transfer = felt_to_starkfelt(Felt::from(BALANCE_AFTER_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
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
            vec![starkfelt_to_felt(balance_after_transfer), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![starkfelt_to_felt(balance_to_transfer), Felt::from(0u128)]
        );
    }

    #[test]
    fn transfer_from_insufficient_allowance() {
        let address_from = Signers::Alice;
        let address_to = Signers::Bob;
        let address_spender = Signers::Charlie;

        let total_supply = felt_to_starkfelt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = felt_to_starkfelt(Felt::from(BALANCE_TO_TRANSFER));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
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
                    felt_to_starkfelt(Felt::from(BALANCE_TO_TRANSFER + 1)),
                    StarkFelt::from(0u128)
                ],
            ),
            vec![Felt::from_hex(U256_UNDERFLOW).unwrap()]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
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

        let total_supply = felt_to_starkfelt(Felt::from(TOTAL_SUPPLY));
        let balance_to_transfer = felt_to_starkfelt(Felt::from(TOTAL_SUPPLY + 1));

        let mut context = TestContext::new().with_caller(address_from.into());

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
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
            vec![Felt::from_hex(U256_UNDERFLOW).unwrap()]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_from.into()]),
            vec![starkfelt_to_felt(total_supply), Felt::from(0u128)]
        );

        assert_eq!(
            context.call_entry_point("balance_of", vec![address_to.into()]),
            vec![Felt::from(0u128), Felt::from(0u128)]
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

        assert_eq!(result, vec![Felt::from_bytes_be_slice(NAME.as_bytes())]);
    }

    #[test]
    fn test_symbol() {
        let mut context = TestContext::new();
        let result = context.call_entry_point("symbol", vec![]);

        assert_eq!(result, vec![Felt::from_bytes_be_slice(SYMBOL.as_bytes())]);
    }

    #[test]
    fn test_decimals() {
        let mut context = TestContext::new();
        let result = context.call_entry_point("decimals", vec![]);

        assert_eq!(result, vec![Felt::from(DECIMALS)]);
    }
}
