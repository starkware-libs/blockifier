use std::path::PathBuf;

use anyhow::Result;
use pretty_assertions::assert_eq;
use starknet_api::core::EntryPointSelector;
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_api::transaction::CallData;

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;

const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/simple_contract_compiled.json";
const WITHOUT_ARG_SELECTOR: &str =
    "0x382a967a31be13f23e23a5345f7a89b0362cc157d6fbe7564e6396a83cf4b4f";
const WITH_ARG_SELECTOR: &str = "0xe7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc";
const BITWISE_AND_SELECTOR: &str =
    "0xad451bd0dba3d8d97104e1bfc474f88605ccc7acbe1c846839a120fdf30d95";
const SQRT_SELECTOR: &str = "0x137a07fa9c479e27114b8ae1fbf252f2065cf91a0d8615272e060a7ccf37309";
const RETURN_RESULT_SELECTOR: &str =
    "0x39a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701";

fn create_test_contract_class() -> ContractClass {
    let path = PathBuf::from(TEST_CONTRACT_PATH);
    ContractClass::from_file(&path).expect("File must contain the content of a compiled contract.")
}

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(WITHOUT_ARG_SELECTOR)?),
        CallData(vec![]),
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

// TODO(Adi, 29/11/2022): Remove the 'StarkFelt::from_u64' conversions once there is a From<u64>
// trait for StarkFelt.
#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(25)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(WITH_ARG_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(47), StarkFelt::from_u64(31)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(BITWISE_AND_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(81)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(SQRT_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(23)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(RETURN_RESULT_SELECTOR)?),
        calldata,
    );
    assert_eq!(entry_point.execute()?, vec![StarkFelt::from_u64(23)]);
    Ok(())
}

#[test]
fn test_entry_point_not_found_in_contract() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_u64(2)),
        CallData(vec![]),
    );
    assert_eq!(
        format!("{}", entry_point.execute().unwrap_err()),
        format!("Entry point {:#?} not found in contract", entry_point.entry_point_selector)
    );
    Ok(())
}
