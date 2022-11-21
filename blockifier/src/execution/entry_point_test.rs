use anyhow::Result;
use cairo_rs::bigint;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use starknet_api::{CallData, StarkFelt};

use crate::execution::entry_point::CallEntryPoint;

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(test_contract, "without_arg", &CallData(vec![]));
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

// TODO(Adi, 29/11/2022): Remove the 'StarkFelt::from_u64' conversions once there is a From<u64>
// trait for StarkFelt.
#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point =
        CallEntryPoint::new(test_contract, "with_arg", &CallData(vec![StarkFelt::from_u64(25)]));
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(
        test_contract,
        "bitwise_and",
        &CallData(vec![StarkFelt::from_u64(47), StarkFelt::from_u64(31)]),
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point =
        CallEntryPoint::new(test_contract, "sqrt", &CallData(vec![StarkFelt::from_u64(81)]));
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let test_contract = "./feature_contracts/compiled/simple_contract.json";
    let entry_point = CallEntryPoint::new(
        test_contract,
        "return_result",
        &CallData(vec![StarkFelt::from_u64(23)]),
    );
    assert_eq!(entry_point.execute()?, vec![bigint!(23)]);
    Ok(())
}
