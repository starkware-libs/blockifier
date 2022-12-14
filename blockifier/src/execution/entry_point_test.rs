use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::Result;
use pretty_assertions::assert_eq;
use starknet_api::core::{ClassHash, EntryPointSelector};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::shash;
use starknet_api::state::EntryPointType;
use starknet_api::transaction::CallData;

use crate::cached_state::{CachedState, DictStateReader};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::CallEntryPoint;

const TEST_CONTRACT_PATH: &str = "./feature_contracts/compiled/simple_contract_compiled.json";
const WITHOUT_ARG_SELECTOR: &str =
    "0x382a967a31be13f23e23a5345f7a89b0362cc157d6fbe7564e6396a83cf4b4f";
const WITH_ARG_SELECTOR: &str = "0xe7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc";
const BITWISE_AND_SELECTOR: &str =
    "0xad451bd0dba3d8d97104e1bfc474f88605ccc7acbe1c846839a120fdf30d95";
const SQRT_SELECTOR: &str = "0x137a07fa9c479e27114b8ae1fbf252f2065cf91a0d8615272e060a7ccf37309";
const RETURN_RESULT_SELECTOR: &str =
    "0x39a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701";
const GET_VALUE_SELECTOR: &str =
    "0x26813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0";
const TEST_LIBRARY_CALL_SELECTOR: &str =
    "0x3604cea1cdb094a73a31144f14a3e5861613c008e1e879939ebc4827d10cd50";
const TEST_CLASS_HASH: &str = "0x1";

// TODO(Noa, 30/12/22): Move it to a test_utils.rs file and use it in cached_state_test.rs (same for
// the relevant constants above)

fn create_test_contract_class() -> ContractClass {
    let path = PathBuf::from(TEST_CONTRACT_PATH);
    ContractClass::from_file(&path).expect("File must contain the content of a compiled contract.")
}

fn create_test_state() -> CachedState<DictStateReader> {
    let class_hash_to_class = HashMap::from([(
        ClassHash(shash!(TEST_CLASS_HASH)),
        Rc::new(create_test_contract_class()),
    )]);
    CachedState::new(DictStateReader { class_hash_to_class, ..Default::default() })
}

fn trivial_external_entrypoint() -> CallEntryPoint {
    CallEntryPoint {
        class_hash: ClassHash(shash!(TEST_CLASS_HASH)),
        entry_point_type: EntryPointType::External,
        entry_point_selector: EntryPointSelector(StarkHash::from(0)),
        calldata: CallData(vec![]),
    }
}

// TODO(AlonH, 21/12/2022): Compare the whole CallInfo in tests.
#[test]
fn test_entry_point_without_arg() -> Result<()> {
    let state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(shash!(WITHOUT_ARG_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state)?.execution.retdata, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_arg() -> Result<()> {
    let state = create_test_state();
    let calldata = CallData(vec![StarkFelt::from(25)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(WITH_ARG_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state)?.execution.retdata, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_builtin() -> Result<()> {
    let state = create_test_state();
    let calldata = CallData(vec![StarkFelt::from(47), StarkFelt::from(31)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(BITWISE_AND_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state)?.execution.retdata, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_hint() -> Result<()> {
    let state = create_test_state();
    let calldata = CallData(vec![StarkFelt::from(81)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(SQRT_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state)?.execution.retdata, Vec::<StarkFelt>::new());
    Ok(())
}

#[test]
fn test_entry_point_with_return_value() -> Result<()> {
    let state = create_test_state();
    let calldata = CallData(vec![StarkFelt::from(23)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(RETURN_RESULT_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state)?.execution.retdata, vec![StarkFelt::from(23)]);
    Ok(())
}

#[test]
fn test_entry_point_not_found_in_contract() -> Result<()> {
    let state = create_test_state();
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(StarkHash::from(2)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(
        format!("{}", entry_point.execute(state).unwrap_err()),
        format!("Entry point {:#?} not found in contract.", entry_point.entry_point_selector)
    );
    Ok(())
}

#[test]
fn test_entry_point_with_syscall() -> Result<()> {
    let state = create_test_state();
    let calldata = CallData(vec![StarkFelt::from(1234)]);
    let entry_point = CallEntryPoint {
        calldata,
        entry_point_selector: EntryPointSelector(shash!(GET_VALUE_SELECTOR)),
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state)?.execution.retdata, vec![StarkFelt::from(18)]);
    Ok(())
}

#[test]
fn test_entry_point_with_library_call() -> Result<()> {
    let state = create_test_state();
    let calldata = CallData(vec![shash!(1), shash!(2), shash!(3), shash!(4), shash!(5), shash!(6)]);
    let entry_point = CallEntryPoint {
        entry_point_selector: EntryPointSelector(StarkHash::try_from(TEST_LIBRARY_CALL_SELECTOR)?),
        calldata,
        ..trivial_external_entrypoint()
    };
    assert_eq!(entry_point.execute(state)?.execution.retdata, vec![shash!(45), shash!(91)]);
    Ok(())
}
