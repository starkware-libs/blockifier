use anyhow::Result;
use cairo_rs::bigint;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;

use crate::execution::entry_point::CallEntryPoint;

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "without_arg", vec![]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "with_arg", vec![25]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "bitwise_and", vec![47, 31]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "sqrt", vec![81]);
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "return_result", vec![23]);
    assert_eq!(entry_point.execute()?, vec![bigint!(23)]);
    Ok(())
}
