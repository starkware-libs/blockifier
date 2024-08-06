use assert_matches::assert_matches;

use crate::execution::contract_class::ContractClass;
use crate::state::state_api::State;
use crate::test_utils::contracts::FeatureContract;

pub fn assert_consistent_contract_version(contract: FeatureContract, state: &dyn State) {
    let hash = contract.get_class_hash();
    match contract {
        FeatureContract::SierraTestContract | FeatureContract::SierraExecutionInfoV1Contract => {
            // Assert contract uses Native
            assert_matches!(
                state
                    .get_compiled_contract_class(hash)
                    .unwrap_or_else(|_| panic!("Expected contract class at {hash}")),
                ContractClass::V1Native(_)
            )
        }
        FeatureContract::SecurityTests
        | FeatureContract::ERC20(_)
        | FeatureContract::LegacyTestContract
        | FeatureContract::AccountWithLongValidate(_)
        | FeatureContract::AccountWithoutValidations(_)
        | FeatureContract::Empty(_)
        | FeatureContract::FaultyAccount(_)
        | FeatureContract::TestContract(_) => {
            // Assert contract uses VM
            assert_matches!(
                state
                    .get_compiled_contract_class(hash)
                    .unwrap_or_else(|_| panic!("Expected contract class at {hash}")),
                ContractClass::V1(_) | ContractClass::V0(_)
            )
        }
    }
}
