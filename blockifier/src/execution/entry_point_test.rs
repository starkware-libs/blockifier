use std::path::PathBuf;

use anyhow::Result;
use cairo_rs::bigint;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;

const TEST_CONTRACT_PROGRAM_PATH: &str =
    "./feature_contracts/compiled/simple_contract_program.json";
const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/simple_contract_compiled.json";

fn initialize_contract_class_for_test() -> ContractClass {
    let path = PathBuf::from(TEST_CONTRACT_PATH);
    ContractClass::from_file(&path).unwrap()
}

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        initialize_contract_class_for_test(),
        TEST_CONTRACT_PROGRAM_PATH,
        "without_arg",
        vec![],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        initialize_contract_class_for_test(),
        TEST_CONTRACT_PROGRAM_PATH,
        "with_arg",
        vec![25],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        initialize_contract_class_for_test(),
        TEST_CONTRACT_PROGRAM_PATH,
        "bitwise_and",
        vec![47, 31],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        initialize_contract_class_for_test(),
        TEST_CONTRACT_PROGRAM_PATH,
        "sqrt",
        vec![81],
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        initialize_contract_class_for_test(),
        TEST_CONTRACT_PROGRAM_PATH,
        "return_result",
        vec![23],
    );
    assert_eq!(entry_point.execute()?, vec![bigint!(23)]);
    Ok(())
}
