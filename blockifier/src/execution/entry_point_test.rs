use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::execution::entry_point::CallEntryPoint;

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "without_arg", vec![]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "with_arg", vec![25]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "bitwise_and", vec![47, 31]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}

#[test]
#[should_panic(expected = "is not an entry point.")]
fn test_non_entry_point_call() {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "with_arg.Args", vec![]);
    let _result = entry_point.execute();
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "sqrt", vec![81]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}
