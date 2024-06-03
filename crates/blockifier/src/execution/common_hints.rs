use std::collections::HashMap;
use std::ops::Shl;
use std::rc::Rc;

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
use cairo_vm::vm::runners::cairo_runner::RunResources;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::BigUint;
use starknet_types_core::felt::Felt;

use crate::execution::hint_code::{
    NORMALIZE_ADDRESS_SET_IS_250_HINT, NORMALIZE_ADDRESS_SET_IS_SMALL_HINT,
};

/// Transaction execution mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, derive_more::Display)]
pub enum ExecutionMode {
    /// Normal execution mode.
    #[default]
    Execute,
    /// Validate execution mode.
    Validate,
}

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
    let addr_bound = &constants
        .get(ADDR_BOUND)
        .ok_or_else(|| HintError::MissingConstant("ADDR_BOUND".into()))?
        .to_biguint();
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?.to_biguint();
    let prime = Felt::prime();

    if !(addr_bound > &BigUint::from(1u8).shl(250)
        && addr_bound <= &BigUint::from(1u8).shl(251)
        && prime > (BigUint::from(2u8) * BigUint::from(1u8).shl(250))
        && prime < (2u8 * addr_bound))
    {
        return Err(HintError::AssertionFailed(
            format!(
                "assert (2**250 < {addr_bound} <= 2**251) and (2 * 2**250 < PRIME) and \
                 ({addr_bound} * 2 > PRIME); normalize_address() cannot be used with the current \
                 constants.",
            )
            .into(),
        ));
    }

    let is_small = if addr < *addr_bound { Felt::ONE } else { Felt::ZERO };
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

    let is_250 = if addr < (Felt::TWO.pow(250_u128)) { Felt::ONE } else { Felt::ZERO };
    insert_value_from_var_name("is_250", is_250, vm, ids_data, ap_tracking)
}

/// Extend the builtin hint processor with common hints.
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
    BuiltinHintProcessor::new(extra_hints, RunResources::default())
}
