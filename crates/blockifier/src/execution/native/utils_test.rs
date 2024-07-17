use ark_ff::BigInt;
use cairo_lang_starknet_classes::contract_class::ContractEntryPoint;
use cairo_native::starknet::U256;
use num_bigint::BigUint;
use num_traits::Num;
use pretty_assertions::assert_eq;
use starknet_api::core::{ContractAddress, EntryPointSelector, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{contract_address, patricia_key};
use starknet_types_core::felt::Felt;

use super::{
    big4int_to_u256, contract_address_to_native_felt, contract_entrypoint_to_entrypoint_selector,
    decode_felts_as_str, encode_str_as_felts, native_felt_to_stark_felt, stark_felt_to_native_felt,
    u256_to_biguint,
};

#[test]
fn test_u256_to_biguint() {
    let u256 = U256 { lo: 0x1234_5678, hi: 0x9abc_def0 };

    let expected_biguint =
        BigUint::from_str_radix("9abcdef000000000000000000000000012345678", 16).unwrap();

    let actual_biguint = u256_to_biguint(u256);

    assert_eq!(actual_biguint, expected_biguint);
}

#[test]
fn big4int_to_u256_test() {
    let big_int: BigInt<4> =
        BigInt!("34627219085299802438030559924718133626325687994345768323532899246965609283226");

    let expected_u256 = U256 {
        lo: 162661716537849136813498421163242372762,
        hi: 101760251048639038778899488808831626319,
    };

    let actual_u256 = big4int_to_u256(big_int);

    assert_eq!(actual_u256, expected_u256);
}

#[test]
fn test_encode_decode_str() {
    const STR: &str = "Hello StarkNet!";

    let encoded_felt_array = encode_str_as_felts(STR);

    let decoded_felt_array = decode_felts_as_str(encoded_felt_array.as_slice());

    assert_eq!(&decoded_felt_array, STR);
}

#[test]
fn test_decode_non_utf8_str() {
    let v1 = Felt::from_dec_str("1234").unwrap();
    let v2_msg = "i am utf8";
    let v2 = Felt::from_bytes_be_slice(v2_msg.as_bytes());
    let v3 = Felt::from_dec_str("13299428").unwrap();
    let felts = [v1, v2, v3];

    let res = decode_felts_as_str(&felts);
    dbg!(res.as_bytes());
    assert_eq!(res, format!("[{}, {} ({}), {}]", v1, v2_msg, v2, v3))
}

#[test]
fn test_felt_to_stark_felt() {
    const NUM: u128 = 123;

    let felt = Felt::from(NUM);
    let expected_stark_felt = StarkFelt::from_u128(NUM);
    let actual_stark_felt = native_felt_to_stark_felt(felt);

    assert_eq!(actual_stark_felt, expected_stark_felt);
}

#[test]
fn test_stark_felt_to_felt() {
    const NUM: u128 = 123;

    let stark_felt = StarkFelt::from_u128(NUM);
    let expected_felt = Felt::from(NUM);
    let actual_felt = stark_felt_to_native_felt(stark_felt);

    assert_eq!(actual_felt, expected_felt);
}

#[test]
fn test_contract_address_to_felt() {
    const NUM: u128 = 1234;

    let contract_address = contract_address!({ NUM });
    let expected_felt = Felt::from(NUM);
    let actual_felt = contract_address_to_native_felt(contract_address);

    assert_eq!(actual_felt, expected_felt);
}

#[test]
fn test_contract_entrypoint_to_entrypoint_selector() {
    const NUM: u128 = 123;

    let entrypoint = ContractEntryPoint { selector: BigUint::from(NUM), function_idx: 0 };
    let expected_entrypoint_selector = EntryPointSelector(StarkFelt::from_u128(NUM));
    let actual_entrypoint_selector = contract_entrypoint_to_entrypoint_selector(&entrypoint);

    assert_eq!(actual_entrypoint_selector, expected_entrypoint_selector);
}
