use std::collections::HashSet;
use std::fs;
use std::sync::Arc;

use assert_matches::assert_matches;
use cairo_lang_starknet_classes::NestedIntList;
use rstest::rstest;

use crate::execution::contract_class::{ContractClassV0, ContractClassV1, ContractClassV1Inner};
use crate::transaction::errors::TransactionExecutionError;

#[rstest]
fn test_get_visited_segments() {
    let test_contract = ContractClassV1(Arc::new(ContractClassV1Inner {
        program: Default::default(),
        entry_points_by_type: Default::default(),
        hints: Default::default(),
        bytecode_segment_lengths: NestedIntList::Node(vec![
            NestedIntList::Leaf(151),
            NestedIntList::Leaf(104),
            NestedIntList::Node(vec![NestedIntList::Leaf(170), NestedIntList::Leaf(225)]),
            NestedIntList::Leaf(157),
            NestedIntList::Node(vec![NestedIntList::Node(vec![
                NestedIntList::Node(vec![NestedIntList::Leaf(101)]),
                NestedIntList::Leaf(195),
                NestedIntList::Leaf(125),
            ])]),
            NestedIntList::Leaf(162),
        ]),
    }));

    assert_eq!(
        test_contract
            .get_visited_segments(&HashSet::from([807, 907, 0, 1, 255, 425, 431, 1103]))
            .unwrap(),
        [0, 255, 425, 807, 1103]
    );

    assert_matches!(
        test_contract
            .get_visited_segments(&HashSet::from([907, 0, 1, 255, 425, 431, 1103]))
            .unwrap_err(),
        TransactionExecutionError::InvalidSegmentStructure(907, 807)
    );
}

#[test]
fn test_deserialization_of_contract_class_v_0() {
    let contract_class: ContractClassV0 =
        serde_json::from_slice(&fs::read("./tests/cairo0/counter.json").unwrap())
            .expect("failed to deserialize contract class from file");

    assert_eq!(contract_class, ContractClassV0::from_file("./tests/cairo0/counter.json"));
}

#[test]
fn test_deserialization_of_contract_class_v_1() {
    let contract_class: ContractClassV1 =
        serde_json::from_slice(&fs::read("./tests/cairo1/counter.json").unwrap())
            .expect("failed to deserialize contract class from file");

    assert_eq!(contract_class, ContractClassV1::from_file("./tests/cairo1/counter.json"));
}
