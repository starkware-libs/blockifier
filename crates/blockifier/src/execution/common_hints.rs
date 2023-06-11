use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::{Shl, Shr};
use std::rc::Rc;

use cairo_felt::{Felt252, PRIME_STR};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::BigUint;
use num_integer::{div_rem, Integer};
use num_traits::{Num, One, Zero};

use super::hint_code::ALON_HINT;
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
    constants: &HashMap<String, Felt252>,
) -> HintExecutionResult {
    const ADDR_BOUND: &str = "starkware.starknet.common.storage.ADDR_BOUND";
    let addr_bound = &constants
        .get(ADDR_BOUND)
        .ok_or_else(|| HintError::MissingConstant("ADDR_BOUND".into()))?
        .to_biguint();

    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?.to_biguint();
    let prime = BigUint::from_str_radix(&PRIME_STR[2..], 16)
        .map_err(|_| VirtualMachineError::CouldntParsePrime(PRIME_STR.into()))?;

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

    let is_small = if addr < *addr_bound { Felt252::one() } else { Felt252::zero() };
    insert_value_from_var_name("is_small", is_small, vm, ids_data, ap_tracking)
}

/// Must comply with the API of a hint function, as defined by the `HintProcessor`.
pub fn normalize_address_set_is_250(
    vm: &mut VirtualMachine,
    _execution_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> HintExecutionResult {
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?;

    let is_250 =
        if *addr < (Felt252::one() << (250_u32)) { Felt252::one() } else { Felt252::zero() };
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
        (ALON_HINT.to_string(), Rc::new(HintFunc(Box::new(alon)))),
    ]);
    BuiltinHintProcessor::new(extra_hints)
}

pub fn alon(
    vm: &mut VirtualMachine,
    _execution_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    uint256_mul_div_mod(vm, ids_data, ap_tracking)
}

pub(crate) struct Uint256<'a> {
    pub low: Cow<'a, Felt252>,
    pub high: Cow<'a, Felt252>,
}

impl<'a> Uint256<'a> {
    pub(crate) fn from_base_addr(
        addr: Relocatable,
        name: &str,
        vm: &'a VirtualMachine,
    ) -> Result<Self, HintError> {
        Ok(Self {
            low: vm.get_integer(addr).map_err(|_| {
                HintError::IdentifierHasNoMember((name.to_string(), "low".to_string()).into())
            })?,
            high: vm.get_integer((addr + 1)?).map_err(|_| {
                HintError::IdentifierHasNoMember((name.to_string(), "high".to_string()).into())
            })?,
        })
    }

    pub(crate) fn from_var_name(
        name: &str,
        vm: &'a VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> Result<Self, HintError> {
        let base_addr = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;
        Self::from_base_addr(base_addr, name, vm)
    }

    pub(crate) fn from_values(low: Felt252, high: Felt252) -> Self {
        let low = Cow::Owned(low);
        let high = Cow::Owned(high);
        Self { low, high }
    }

    pub(crate) fn insert_from_var_name(
        self,
        var_name: &str,
        vm: &mut VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> Result<(), HintError> {
        let addr = get_relocatable_from_var_name(var_name, vm, ids_data, ap_tracking)?;

        vm.insert_value(addr, self.low.into_owned())?;
        vm.insert_value((addr + 1)?, self.high.into_owned())?;

        Ok(())
    }

    pub(crate) fn split(num: &BigUint) -> Self {
        let mask_low: BigUint = u128::MAX.into();
        let low = Felt252::from(num & mask_low);
        let high = Felt252::from(num >> 128);
        Self::from_values(low, high)
    }
}

impl<'a> From<&BigUint> for Uint256<'a> {
    fn from(value: &BigUint) -> Self {
        Self::split(value)
    }
}

impl<'a> From<Felt252> for Uint256<'a> {
    fn from(value: Felt252) -> Self {
        let low = Felt252::new(u128::MAX) & &value;
        let high = value >> 128;
        Self::from_values(low, high)
    }
}

pub fn uint256_offseted_unsigned_div_rem(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    div_offset_low: usize,
    div_offset_high: usize,
) -> Result<(), HintError> {
    let a = Uint256::from_var_name("a", vm, ids_data, ap_tracking)?;
    let a_low = a.low.as_ref();
    let a_high = a.high.as_ref();

    let div_addr = get_relocatable_from_var_name("div", vm, ids_data, ap_tracking)?;
    let div_low = vm.get_integer((div_addr + div_offset_low)?)?;
    let div_high = vm.get_integer((div_addr + div_offset_high)?)?;
    let div_low = div_low.as_ref();
    let div_high = div_high.as_ref();

    // Main logic
    // a = (ids.a.high << 128) + ids.a.low
    // div = (ids.div.high << 128) + ids.div.low
    // quotient, remainder = divmod(a, div)

    // ids.quotient.low = quotient & ((1 << 128) - 1)
    // ids.quotient.high = quotient >> 128
    // ids.remainder.low = remainder & ((1 << 128) - 1)
    // ids.remainder.high = remainder >> 128
    let a = (a_high.to_biguint() << 128_u32) + a_low.to_biguint();
    let div = (div_high.to_biguint() << 128_u32) + div_low.to_biguint();
    // a and div will always be positive numbers
    // Then, Rust div_rem equals Python divmod
    let (quotient, remainder) = div_rem(a, div);

    let quotient = Uint256::from(&quotient);
    let remainder = Uint256::from(&remainder);
    // dbg!(&quotient.low);
    // dbg!(&quotient.high);
    // dbg!(&remainder.low);
    // dbg!(&remainder.high);

    quotient.insert_from_var_name("quotient", vm, ids_data, ap_tracking)?;
    remainder.insert_from_var_name("remainder", vm, ids_data, ap_tracking)?;

    Ok(())
}

pub fn uint256_mul_div_mod(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    // Extract variables
    let a_addr = get_relocatable_from_var_name("a", vm, ids_data, ap_tracking)?;
    let b_addr = get_relocatable_from_var_name("b", vm, ids_data, ap_tracking)?;
    let div_addr = get_relocatable_from_var_name("div", vm, ids_data, ap_tracking)?;
    let quotient_low_addr =
        get_relocatable_from_var_name("quotient_low", vm, ids_data, ap_tracking)?;
    let quotient_high_addr =
        get_relocatable_from_var_name("quotient_high", vm, ids_data, ap_tracking)?;
    let remainder_addr = get_relocatable_from_var_name("remainder", vm, ids_data, ap_tracking)?;

    let a_low = vm.get_integer(a_addr)?;
    let a_high = vm.get_integer((a_addr + 1_usize)?)?;
    let b_low = vm.get_integer(b_addr)?;
    let b_high = vm.get_integer((b_addr + 1_usize)?)?;
    let div_low = vm.get_integer(div_addr)?;
    let div_high = vm.get_integer((div_addr + 1_usize)?)?;
    let a_low = a_low.as_ref();
    let a_high = a_high.as_ref();
    let b_low = b_low.as_ref();
    let b_high = b_high.as_ref();
    let div_low = div_low.as_ref();
    let div_high = div_high.as_ref();
    dbg!(&a_low);
    dbg!(&a_high);
    dbg!(&b_low);
    dbg!(&b_high);
    dbg!(&div_low);
    dbg!(&div_high);

    // Main Logic
    let a = a_high.to_biguint().shl(128_usize) + a_low.to_biguint();
    let b = b_high.to_biguint().shl(128_usize) + b_low.to_biguint();
    let div = div_high.to_biguint().shl(128_usize) + div_low.to_biguint();
    let (quotient, remainder) = (a * b).div_mod_floor(&div);

    // ids.quotient_low.low
    vm.insert_value(
        quotient_low_addr,
        Felt252::from(&quotient & &BigUint::from(u128::MAX)),
    )?;
    // ids.quotient_low.high
    vm.insert_value(
        (quotient_low_addr + 1)?,
        Felt252::from((&quotient).shr(128_u32) & &BigUint::from(u128::MAX)),
    )?;
    // ids.quotient_high.low
    vm.insert_value(
        quotient_high_addr,
        Felt252::from((&quotient).shr(256_u32) & &BigUint::from(u128::MAX)),
    )?;
    // ids.quotient_high.high
    vm.insert_value(
        (quotient_high_addr + 1)?,
        Felt252::from((&quotient).shr(384_u32)),
    )?;
    //ids.remainder.low
    vm.insert_value(
        remainder_addr,
        Felt252::from(&remainder & &BigUint::from(u128::MAX)),
    )?;
    //ids.remainder.high
    vm.insert_value((remainder_addr + 1)?, Felt252::from(remainder.shr(128_u32)))?;

    Ok(())
}
