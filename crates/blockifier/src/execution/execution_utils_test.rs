use cairo_felt::Felt;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use pretty_assertions::assert_eq;
use starknet_api::hash::StarkFelt;

use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};

fn get_tested_felts_and_corresponding_bigints() -> (Vec<StarkFelt>, Vec<Felt>) {
    // The STARK prime is 2 ^ 251 + 17 * 2 ^ 192 + 1.
    const STARK_PRIME: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
    const STARK_PRIME_MINUS_ONE: &str =
        "0x800000000000011000000000000000000000000000000000000000000000000";

    let felt_from_hex_error_message = "`StarkFelt` construction from hex has failed.";
    let felts = vec![
        StarkFelt::from(0),
        StarkFelt::from(1),
        StarkFelt::from(1234),
        StarkFelt::try_from(STARK_PRIME).expect(felt_from_hex_error_message),
        StarkFelt::try_from(STARK_PRIME_MINUS_ONE).expect(felt_from_hex_error_message),
    ];
    let bigints = vec![
        Felt::zero(),
        Felt::one(),
        Felt::from(1234),
        // Note: the BigUint digits are ordered least significant digit first.
        // Prime.
        Felt::from(BigUint::new(vec![1, 0, 0, 0, 0, 0, 17, 134217728])),
        // Prime - 1.
        Felt::from(BigUint::new(vec![0, 0, 0, 0, 0, 0, 17, 134217728])),
    ];

    (felts, bigints)
}

#[test]
fn test_stark_felt_to_felt() {
    let (felts, expected_bigints) = get_tested_felts_and_corresponding_bigints();
    let converted_bigints: Vec<Felt> = felts.iter().map(|x| stark_felt_to_felt(*x)).collect();

    assert_eq!(converted_bigints, expected_bigints);
}

#[test]
fn test_felt_to_stark_felt() {
    let (expected_felts, bigints) = get_tested_felts_and_corresponding_bigints();
    // Positive flow.
    let converted_felts: Vec<StarkFelt> = bigints.iter().map(felt_to_stark_felt).collect();

    assert_eq!(converted_felts, expected_felts);
}
