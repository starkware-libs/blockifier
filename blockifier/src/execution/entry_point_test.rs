use cairo_rs::vm::errors::cairo_run_errors::CairoRunError;
use pretty_assertions::assert_eq;

use crate::execution::entry_point::CallEntryPoint;

#[test]
fn test_entry_point() -> Result<(), Box<CairoRunError>> {
    let test_contract_path = "./test_contracts/array_sum.json";
    let entry_point = CallEntryPoint::new(test_contract_path, "main");
    assert_eq!(entry_point.execute()?, ());
    Ok(())
}
