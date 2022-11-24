use std::path::PathBuf;

use anyhow::Result;
use cairo_rs::bigint;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use starknet_api::{EntryPointSelector, EntryPointType, StarkHash};

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;

const TEST_CONTRACT_PROGRAM_PATH: &str =
    "./feature_contracts/compiled/simple_contract_program.json";
const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/simple_contract_compiled.json";

fn create_test_contract_class() -> ContractClass {
    let path = PathBuf::from(TEST_CONTRACT_PATH);
    ContractClass::from_file(&path).expect("File must contain the content of a compiled contract.")
}

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    // without_arg
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(
            "0x382a967a31be13f23e23a5345f7a89b0362cc157d6fbe7564e6396a83cf4b4f",
        )?),
        vec![],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    // with_arg
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(
            "0xe7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc",
        )?),
        vec![25],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    // bitwise_and
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(
            "0xad451bd0dba3d8d97104e1bfc474f88605ccc7acbe1c846839a120fdf30d95",
        )?),
        vec![47, 31],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    // sqrt
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(
            "0x137a07fa9c479e27114b8ae1fbf252f2065cf91a0d8615272e060a7ccf37309",
        )?),
        vec![81],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    // return_result
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        EntryPointType::External,
        EntryPointSelector(StarkHash::from_hex(
            "0x39a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
        )?),
        vec![23],
    );
    assert_eq!(entry_point.execute()?, vec![bigint!(23)]);
    Ok(())
}
