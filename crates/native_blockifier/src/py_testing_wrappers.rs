use blockifier::execution::contract_class::estimate_casm_hash_computation_resources;
use blockifier::transaction::errors::{TransactionExecutionError, TransactionFeeError};
use cairo_lang_starknet_classes::NestedIntList;
use pyo3::{pyfunction, PyResult};

use crate::errors::NativeBlockifierResult;
use crate::py_objects::PyExecutionResources;

#[pyfunction]
pub fn raise_error_for_testing() -> NativeBlockifierResult<()> {
    Err(TransactionExecutionError::TransactionFeeError(
        TransactionFeeError::CairoResourcesNotContainedInFeeCosts,
    )
    .into())
}

/// Wrapper for [estimate_casm_hash_computation_resources] that can be used for testing.
/// Takes a leaf.
#[pyfunction]
pub fn estimate_casm_hash_computation_resources_for_testing_single(
    bytecode_segment_lengths: usize,
) -> PyResult<PyExecutionResources> {
    let node = NestedIntList::Leaf(bytecode_segment_lengths);
    Ok(estimate_casm_hash_computation_resources(&node).into())
}

/// Wrapper for [estimate_casm_hash_computation_resources] that can be used for testing.
/// Takes a node of leaves.
#[pyfunction]
pub fn estimate_casm_hash_computation_resources_for_testing_list(
    bytecode_segment_lengths: Vec<usize>,
) -> PyResult<PyExecutionResources> {
    let node = NestedIntList::Node(
        bytecode_segment_lengths.into_iter().map(NestedIntList::Leaf).collect(),
    );
    Ok(estimate_casm_hash_computation_resources(&node).into())
}
