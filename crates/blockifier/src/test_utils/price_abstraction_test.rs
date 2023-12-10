use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pretty_assertions::assert_eq;
use rstest::rstest;

use crate::test_utils::price_abstraction::validate_resources;
use crate::test_utils::CairoVersion;

#[rstest]
fn test_validate_resources(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let expected_resources = match cairo_version {
        CairoVersion::Cairo0 => VmExecutionResources {
            n_steps: 21,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
            ..Default::default()
        },
        CairoVersion::Cairo1 => VmExecutionResources {
            n_steps: 141,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 6)]),
        },
    };
    assert_eq!(validate_resources(cairo_version), expected_resources);
}
