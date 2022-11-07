use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::execution::entry_point::CallEntryPoint;

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let test_contract = "./test_contracts/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "without_arg", vec![]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let test_contract = "./test_contracts/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "with_arg", vec![25]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}
