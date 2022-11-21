use std::path::PathBuf;

use anyhow::Result;
use cairo_rs::bigint;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;

const TEST_CONTRACT_PROGRAM: &str = "./feature_contracts/compiled/simple_contract_program.json";
const TEST_CONTRACT: &str = "./feature_contracts/compiled/simple_contract_compiled.json";

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let path = PathBuf::from(TEST_CONTRACT);
    let contract_class = ContractClass::from_file(&path)?;
    let entry_point =
        CallEntryPoint::new(contract_class, TEST_CONTRACT_PROGRAM, "without_arg", vec![]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let path = PathBuf::from(TEST_CONTRACT);
    let contract_class = ContractClass::from_file(&path)?;
    let entry_point =
        CallEntryPoint::new(contract_class, TEST_CONTRACT_PROGRAM, "with_arg", vec![25]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let path = PathBuf::from(TEST_CONTRACT);
    let contract_class = ContractClass::from_file(&path)?;
    let entry_point =
        CallEntryPoint::new(contract_class, TEST_CONTRACT_PROGRAM, "bitwise_and", vec![47, 31]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let path = PathBuf::from(TEST_CONTRACT);
    let contract_class = ContractClass::from_file(&path)?;
    let entry_point = CallEntryPoint::new(contract_class, TEST_CONTRACT_PROGRAM, "sqrt", vec![81]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let path = PathBuf::from(TEST_CONTRACT);
    let contract_class = ContractClass::from_file(&path)?;
    let entry_point =
        CallEntryPoint::new(contract_class, TEST_CONTRACT_PROGRAM, "return_result", vec![23]);
    assert_eq!(entry_point.execute()?, vec![bigint!(23)]);
    Ok(())
}
