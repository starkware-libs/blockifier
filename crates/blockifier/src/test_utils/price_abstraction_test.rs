use std::collections::HashMap;

use cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use pretty_assertions::assert_eq;
use rstest::rstest;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, TransactionVersion};
use starknet_api::{calldata, stark_felt};

use crate::block_context::BlockContext;
use crate::test_utils::price_abstraction::validate_resources;
use crate::test_utils::CairoVersion;

#[rstest]
fn test_validate_resources(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
    #[values(TransactionVersion::ONE, TransactionVersion::THREE)] tx_version: TransactionVersion,
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
            ..Default::default()
        },
    };
    assert_eq!(
        validate_resources(
            &BlockContext::create_for_account_testing(),
            cairo_version,
            tx_version,
            calldata![stark_felt!("0xdead"), stark_felt!("0xbeef"), stark_felt!(0_u8)]
        ),
        expected_resources
    );
}
