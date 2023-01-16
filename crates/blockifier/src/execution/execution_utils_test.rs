use std::iter::zip;

use cairo_felt::Felt;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use pretty_assertions::assert_eq;
use starknet_api::hash::StarkFelt;

use crate::execution::execution_utils::{felt_to_stark_felt, stark_felt_to_felt};

fn felt_to_bigint_pairs() -> Vec<(StarkFelt, Felt)> {
    // The STARK prime is 2 ^ 251 + 17 * 2 ^ 192 + 1.
    const STARK_PRIME: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
    const STARK_PRIME_MINUS_ONE: &str =
        "0x800000000000011000000000000000000000000000000000000000000000000";

    let felt_from_hex_error_message = "`StarkFelt` construction from hex has failed.";
    let felts = vec![
        StarkFelt::from(0),
        StarkFelt::from(1),
        StarkFelt::from(1234),
        // TODO(Adi, 10/12/2022): The construction of a StarkFelt holding the STARK prime should
        // fail once full-node have a field representation; remove this test case.
        StarkFelt::try_from(STARK_PRIME).expect(felt_from_hex_error_message),
        StarkFelt::try_from(STARK_PRIME_MINUS_ONE).expect(felt_from_hex_error_message),
    ];
    let bigints = vec![
        Felt::zero(),
        Felt::one(),
        Felt::from(1234),
        // This prime constant is taken from examples in the cairo-rs crate.
        // Note: the BigInt digits are ordered least significant digit first.
        Felt::from(BigUint::new(vec![1, 0, 0, 0, 0, 0, 17, 134217728])),
        Felt::from(BigUint::new(vec![0, 0, 0, 0, 0, 0, 17, 134217728])),
    ];

    zip(felts.into_iter(), bigints.into_iter()).collect()
}

#[test]
fn test_stark_felt_to_felt() {
    for (stark_felt, equivalent_felt) in felt_to_bigint_pairs() {
        assert_eq!(stark_felt_to_felt(stark_felt), equivalent_felt);
    }
}

#[test]
fn test_felt_to_stark_felt() {
    for (equivalent_stark_felt, felt) in felt_to_bigint_pairs() {
        assert_eq!(felt_to_stark_felt(&felt), equivalent_stark_felt);
    }
}
