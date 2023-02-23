use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::{create_test_state_util, DictStateReader};

pub const TOKEN_FOR_TESTING_CLASS_HASH: &str = "0x30";
pub const TOKEN_FOR_TESTING_CONTRACT_PATH: &str =
    "./native_blockifier/py_feature_contracts/token_for_testing.json";
pub const TOKEN_FOR_TESTING_CONTRACT_ADDRESS: &str = "0x64";

pub fn create_py_test_state() -> CachedState<DictStateReader> {
    create_test_state_util(
        TOKEN_FOR_TESTING_CLASS_HASH,
        TOKEN_FOR_TESTING_CONTRACT_PATH,
        TOKEN_FOR_TESTING_CONTRACT_ADDRESS,
    )
}
