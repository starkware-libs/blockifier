use std::iter::zip;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use pretty_assertions::assert_eq;
use starknet_types_core::felt::Felt;

fn felt_to_felt_pairs() -> Vec<(Felt, Felt)> {
    // The STARK prime is 2 ^ 251 + 17 * 2 ^ 192 + 1.
    const STARK_PRIME_MINUS_ONE: &str =
        "0x800000000000011000000000000000000000000000000000000000000000000";

    let felt_from_hex_error_message = "`Felt` construction from hex has failed.";
    let felts1 = vec![
        Felt::ZERO,
        Felt::ONE,
        Felt::from(1234_u16),
        Felt::from_hex(STARK_PRIME_MINUS_ONE).expect(felt_from_hex_error_message),
    ];
    let felts2 = vec![
        Felt::zero(),
        Felt::one(),
        Felt::from(1234),
        // Note: the BigUint digits are ordered least significant digit first.
        // Prime - 1.
        Felt::from(BigUint::new(vec![0, 0, 0, 0, 0, 0, 17, 134217728])),
    ];

    zip(felts1, felts2).collect()
}

#[test]
fn test_stark_felt_to_felt() {
    for (stark_felt, equivalent_felt) in felt_to_felt_pairs() {
        assert_eq!(stark_felt, equivalent_felt);
    }
}

#[test]
fn test_felt_to_stark_felt() {
    for (equivalent_stark_felt, felt) in felt_to_felt_pairs() {
        assert_eq!(felt, equivalent_stark_felt);
    }
}
