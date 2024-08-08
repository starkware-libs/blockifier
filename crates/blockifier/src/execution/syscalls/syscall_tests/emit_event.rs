use itertools::concat;
use pretty_assertions::assert_eq;
use starknet_api::felt;
use starknet_api::transaction::{Calldata, EventContent, EventData, EventKey};
use starknet_types_core::felt::Felt;
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, CallInfo, OrderedEvent};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::EntryPointExecutionError;
use crate::execution::native::utils::NATIVE_GAS_PLACEHOLDER;
use crate::execution::syscalls::hint_processor::EmitEventError;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{trivial_external_entry_point_new, CairoVersion, BALANCE};
use crate::versioned_constants::VersionedConstants;

const KEYS: [Felt; 2] = [Felt::from_hex_unchecked("0x2019"), Felt::from_hex_unchecked("0x2020")];
const DATA: [Felt; 3] = [
    Felt::from_hex_unchecked("0x2021"),
    Felt::from_hex_unchecked("0x2022"),
    Felt::from_hex_unchecked("0x2023"),
];
const N_EMITTED_EVENTS: [Felt; 1] = [Felt::from_hex_unchecked("0x1")];

#[test_case(FeatureContract::SierraTestContract, NATIVE_GAS_PLACEHOLDER; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), 49860; "VM")]
fn positive_flow(test_contract: FeatureContract, expected_gas: u64) {
    // TODO(Ori, 1/2/2024): Write an indicative expect message explaining why the conversion
    // works.
    let call_info = emit_events(test_contract, &N_EMITTED_EVENTS, &KEYS, &DATA).unwrap();
    let event = EventContent {
        keys: KEYS.into_iter().map(EventKey).collect(),
        data: EventData(DATA.to_vec()),
    };

    assert_eq!(
        call_info.execution,
        CallExecution {
            events: vec![OrderedEvent { order: 0, event }],
            gas_consumed: expected_gas,
            ..Default::default()
        }
    );
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn data_length_exceeds_limit(test_contract: FeatureContract) {
    let versioned_constants = VersionedConstants::create_for_testing();

    let max_event_data_length = versioned_constants.tx_event_limits.max_data_length;
    let data_too_long = vec![felt!(2_u16); max_event_data_length + 1];
    let error = emit_events(test_contract, &N_EMITTED_EVENTS, &KEYS, &data_too_long).unwrap_err();
    let expected_error = EmitEventError::ExceedsMaxDataLength {
        data_length: max_event_data_length + 1,
        max_data_length: max_event_data_length,
    };
    assert!(error.to_string().contains(&expected_error.to_string()));
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn keys_length_exceeds_limit(test_contract: FeatureContract) {
    let versioned_constants = VersionedConstants::create_for_testing();

    let max_event_keys_length = versioned_constants.tx_event_limits.max_keys_length;
    let keys_too_long = vec![felt!(1_u16); max_event_keys_length + 1];
    let error = emit_events(test_contract, &N_EMITTED_EVENTS, &keys_too_long, &DATA).unwrap_err();
    let expected_error = EmitEventError::ExceedsMaxKeysLength {
        keys_length: max_event_keys_length + 1,
        max_keys_length: max_event_keys_length,
    };

    assert!(error.to_string().contains(&expected_error.to_string()));
}

#[test_case(FeatureContract::SierraTestContract; "Native")]
#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1); "VM")]
fn event_number_exceeds_limit(test_contract: FeatureContract) {
    let versioned_constants = VersionedConstants::create_for_testing();

    let max_n_emitted_events = versioned_constants.tx_event_limits.max_n_emitted_events;
    let n_emitted_events_too_big = vec![felt!(
        u16::try_from(max_n_emitted_events + 1).expect("Failed to convert usize to u16.")
    )];
    let error = emit_events(test_contract, &n_emitted_events_too_big, &KEYS, &DATA).unwrap_err();
    let expected_error = EmitEventError::ExceedsMaxNumberOfEmittedEvents {
        n_emitted_events: max_n_emitted_events + 1,
        max_n_emitted_events,
    };
    assert!(error.to_string().contains(&expected_error.to_string()));
}

fn emit_events(
    test_contract: FeatureContract,
    n_emitted_events: &[Felt],
    keys: &[Felt],
    data: &[Felt],
) -> Result<CallInfo, EntryPointExecutionError> {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);
    let calldata = Calldata(
        concat(vec![
            n_emitted_events.to_owned(),
            vec![felt!(u16::try_from(keys.len()).expect("Failed to convert usize to u16."))],
            keys.to_vec(),
            vec![felt!(u16::try_from(data.len()).expect("Failed to convert usize to u16."))],
            data.to_vec(),
        ])
        .into(),
    );

    let entry_point_call = CallEntryPoint {
        entry_point_selector: selector_from_name("test_emit_events"),
        calldata,
        ..trivial_external_entry_point_new(test_contract)
    };

    entry_point_call.execute_directly(&mut state)
}
