use std::path::PathBuf;

use anyhow::Result;
use pretty_assertions::assert_eq;
use starknet_api::StarkFelt;

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
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "without_arg",
        vec![],
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "with_arg",
        vec![25],
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "bitwise_and",
        vec![47, 31],
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "sqrt",
        vec![81],
    );
    assert_eq!(entry_point.execute()?, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "return_result",
        vec![23],
    );
    assert_eq!(entry_point.execute()?, vec![StarkFelt::from_u64(23)]);
    Ok(())
}
