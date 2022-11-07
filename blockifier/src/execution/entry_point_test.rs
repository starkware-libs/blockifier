use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;
use pretty_assertions::assert_eq;

use crate::execution::entry_point::CallEntryPoint;

#[test]
fn test_entry_point() -> Result<(), Box<CairoRunError>> {
    let test_contract = "./test_contracts/not_main.json";
    let entry_point = CallEntryPoint::new(test_contract, "main", vec![]);
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}
