use std::collections::HashMap;
use std::ops::Shl;
use std::rc::Rc;

use cairo_rs::bigint;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_rs::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, insert_value_from_var_name,
};
use cairo_rs::hint_processor::hint_processor_definition::HintReference;
use cairo_rs::serde::deserialize_program::ApTracking;
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;

const NORMALIZE_ADDRESS_SET_IS_SMALL_HINT: &str = r#"# Verify the assumptions on the relationship between 2**250, ADDR_BOUND and PRIME.
ADDR_BOUND = ids.ADDR_BOUND % PRIME
assert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (
        ADDR_BOUND * 2 > PRIME), \
    'normalize_address() cannot be used with the current constants.'
ids.is_small = 1 if ids.addr < ADDR_BOUND else 0"#;

const NORMALIZE_ADDRESS_SET_IS_250_HINT: &str = "ids.is_250 = 1 if ids.addr < 2**250 else 0";

const ADDR_BOUND: &str = "starkware.starknet.common.storage.ADDR_BOUND";

/// Implements hint:
/// %{
///    # Verify the assumptions on the relationship between 2**250, ADDR_BOUND and PRIME.
///    ADDR_BOUND = ids.ADDR_BOUND % PRIME
///    assert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (
///            ADDR_BOUND * 2 > PRIME), \
///        'normalize_address() cannot be used with the current constants.'
///    ids.is_small = 1 if ids.addr < ADDR_BOUND else 0
/// %}
///
/// Must comply with the API of a hint function, as defined by the `HintProcessor`.
pub fn normalize_address_set_is_small(
    vm: &mut VirtualMachine,
    _execution_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let addr_bound =
        constants.get(ADDR_BOUND).ok_or(VirtualMachineError::MissingConstant("ADDR_BOUND"))?;
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?;

    let prime = vm.get_prime();
    let addr_bound = &addr_bound.mod_floor(prime);
    if addr_bound <= &bigint!(1).shl(250)
        || addr_bound > &bigint!(1).shl(251)
        || prime <= &(bigint!(2) * bigint!(1).shl(250))
        || &(2 * addr_bound) <= prime
    {
        return Err(VirtualMachineError::AssertionFailed(format!(
            "assert (2**250 < {} <= 2**251) and (2 * 2**250 < PRIME) and (
            {} * 2 > PRIME); normalize_address() cannot be used with the current constants.",
            addr_bound, addr_bound
        )));
    }

    let is_small = if *addr < *addr_bound { bigint!(1) } else { bigint!(0) };
    insert_value_from_var_name("is_small", is_small, vm, ids_data, ap_tracking)
}

/// Implements hint:
/// %{
///    ids.is_250 = 1 if ids.addr < 2**250 else 0
/// %}
///
/// Must comply with the API of a hint function, as defined by the `HintProcessor`.
pub fn normalize_address_set_is_250(
    vm: &mut VirtualMachine,
    _execution_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?;

    let is_250 = if *addr < bigint!(1).shl(250) { bigint!(1) } else { bigint!(0) };
    insert_value_from_var_name("is_250", is_250, vm, ids_data, ap_tracking)
}

pub fn add_common_hints(hint_processor: &mut BuiltinHintProcessor) {
    hint_processor.add_hint(
        String::from(NORMALIZE_ADDRESS_SET_IS_SMALL_HINT),
        Rc::new(HintFunc(Box::new(normalize_address_set_is_small))),
    );
    hint_processor.add_hint(
        String::from(NORMALIZE_ADDRESS_SET_IS_250_HINT),
        Rc::new(HintFunc(Box::new(normalize_address_set_is_250))),
    );
}
