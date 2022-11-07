use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::execution::entry_point::CallEntryPoint;

#[test]
fn test_main_entry_point() -> Result<()> {
    let test_contract = "./test_contracts/not_main.json";
    let entry_point = CallEntryPoint::new(test_contract, "main", vec![]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}

#[test]
fn test_not_main_entry_point_with_args() -> Result<()> {
    let test_contract = "./test_contracts/not_main.json";
    let entry_point = CallEntryPoint::new(test_contract, "not_main", vec![25]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}
