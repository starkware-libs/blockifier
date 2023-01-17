use std::collections::HashMap;
use std::rc::Rc;

use cairo_felt::Felt;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_traits::{One, Zero};

use crate::execution::hint_code::{
    NORMALIZE_ADDRESS_SET_IS_250_HINT, NORMALIZE_ADDRESS_SET_IS_SMALL_HINT,
};

pub type HintExecutionResult = Result<(), HintError>;

/// Must comply with the API of a hint function, as defined by the `HintProcessor`.
pub fn normalize_address_set_is_small(
    vm: &mut VirtualMachine,
    _execution_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt>,
) -> HintExecutionResult {
    const ADDR_BOUND: &str = "starkware.starknet.common.storage.ADDR_BOUND";
    let addr_bound = constants.get(ADDR_BOUND).ok_or(HintError::MissingConstant("ADDR_BOUND"))?;
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?;

    // let prime = vm.get_prime();
    // let addr_bound = &addr_bound.mod_floor(prime);
    // if addr_bound <= &bigint!(1).shl(250)
    //     || addr_bound > &bigint!(1).shl(251)
    //     || prime <= &(bigint!(2) * bigint!(1).shl(250))
    //     || &(2 * addr_bound) <= prime
    // {
    //     return Err(HintError::AssertionFailed(format!(
    //         "assert (2**250 < {} <= 2**251) and (2 * 2**250 < PRIME) and (
    //         {} * 2 > PRIME); normalize_address() cannot be used with the current constants.",
    //         addr_bound, addr_bound
    //     )));
    // }

    let is_small = if *addr < *addr_bound { Felt::one() } else { Felt::zero() };
    insert_value_from_var_name("is_small", is_small, vm, ids_data, ap_tracking)
}

/// Must comply with the API of a hint function, as defined by the `HintProcessor`.
pub fn normalize_address_set_is_250(
    vm: &mut VirtualMachine,
    _execution_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt>,
) -> HintExecutionResult {
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?;

    let is_250 = if *addr < (Felt::one() << (250_u32)) { Felt::one() } else { Felt::zero() };
    insert_value_from_var_name("is_250", is_250, vm, ids_data, ap_tracking)
}

/// Extend `BuiltinHintProcessor` with common hints.
pub fn extended_builtin_hint_processor() -> BuiltinHintProcessor {
    let extra_hints: HashMap<String, Rc<HintFunc>> = HashMap::from([
        (
            NORMALIZE_ADDRESS_SET_IS_SMALL_HINT.to_string(),
            Rc::new(HintFunc(Box::new(normalize_address_set_is_small))),
        ),
        (
            NORMALIZE_ADDRESS_SET_IS_250_HINT.to_string(),
            Rc::new(HintFunc(Box::new(normalize_address_set_is_250))),
        ),
    ]);
    BuiltinHintProcessor::new(extra_hints)
}
