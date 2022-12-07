use anyhow::Result;
use pretty_assertions::assert_eq;
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::CallData;

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;
use crate::transaction::transaction_utils::get_contract_class;

const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/simple_contract_compiled.json";
const WITHOUT_ARG_SELECTOR: &str =
    "0x382a967a31be13f23e23a5345f7a89b0362cc157d6fbe7564e6396a83cf4b4f";
const WITH_ARG_SELECTOR: &str = "0xe7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc";
const BITWISE_AND_SELECTOR: &str =
    "0xad451bd0dba3d8d97104e1bfc474f88605ccc7acbe1c846839a120fdf30d95";
const SQRT_SELECTOR: &str = "0x137a07fa9c479e27114b8ae1fbf252f2065cf91a0d8615272e060a7ccf37309";
const RETURN_RESULT_SELECTOR: &str =
    "0x39a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701";
const GET_VALUE_SELECTOR: &str =
    "0x26813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0";

fn create_test_contract_class() -> ContractClass {
    get_contract_class(TEST_CONTRACT_PATH)
}

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::try_from(WITHOUT_ARG_SELECTOR)?),
        CallData(vec![]),
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from(25)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::try_from(WITH_ARG_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from(47), StarkFelt::from(31)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::try_from(BITWISE_AND_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from(81)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::try_from(SQRT_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from(23)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::try_from(RETURN_RESULT_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, vec![StarkFelt::from(23)]);
    Ok(())
}

#[test]
fn test_entry_point_not_found_in_contract() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::from(2)),
        CallData(vec![]),
    );
    assert_eq!(
        format!("{}", entry_point.execute().unwrap_err()),
        format!("Entry point {:#?} not found in contract", entry_point.entry_point_selector)
    );
    Ok(())
}

#[test]
fn test_entry_point_with_syscall() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::try_from(GET_VALUE_SELECTOR)?),
        CallData(vec![StarkFelt::from(1234)]),
    );
    assert_eq!(entry_point.execute()?, vec![StarkFelt::from(17)]);
    Ok(())
}
