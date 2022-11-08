use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::execution::entry_point::EntryPoint;

#[test]
fn test_entry_point() -> Result<()> {
    let test_contract = "./test_contracts/array_sum.json";
    let entry_point = EntryPoint::new(test_contract, "main");
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}
