use std::path::PathBuf;

use anyhow::Result;
use cairo_rs::bigint;
use num_bigint::BigInt;
use pretty_assertions::assert_eq;
use starknet_api::{CallData, StarkFelt};

use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;

const TEST_CONTRACT_PROGRAM_PATH: &str =
    "./feature_contracts/compiled/simple_contract_program.json";
const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/simple_contract_compiled.json";

fn create_test_contract_class() -> ContractClass {
    let path = PathBuf::from(TEST_CONTRACT_PATH);
    ContractClass::from_file(&path).expect("File must contain the content of a compiled contract.")
}

#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "without_arg",
        CallData(vec![]),
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

// TODO(Adi, 29/11/2022): Remove the 'StarkFelt::from_u64' conversions once there is a From<u64>
// trait for StarkFelt.
#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(25)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "with_arg",
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(47), StarkFelt::from_u64(31)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "bitwise_and",
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(81)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "sqrt",
        calldata,
    );
    assert_eq!(entry_point.execute()?, Vec::<BigInt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let calldata = CallData(vec![StarkFelt::from_u64(23)]);
    let entry_point = CallEntryPoint::new(
        create_test_contract_class(),
        TEST_CONTRACT_PROGRAM_PATH,
        "return_result",
        calldata,
    );
    assert_eq!(entry_point.execute()?, vec![bigint!(23)]);
    Ok(())
}
