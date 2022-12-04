use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use starknet_api::hash::StarkFelt;

use crate::execution::cairo_run_utils::{bigint_to_felt, felt_to_bigint};

fn get_tested_felts_and_corresponding_bigints() -> (Vec<StarkFelt>, Vec<BigInt>) {
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
        BigInt::zero(),
        BigInt::one(),
        BigInt::new(Sign::Plus, vec![1234]),
        // This prime constant is taken from examples in the cairo-rs crate.
        // Note: the BigInt digits are ordered least significant digit first.
        BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        BigInt::new(Sign::Plus, vec![0, 0, 0, 0, 0, 0, 17, 134217728]),
    ];

    (felts, bigints)
}

#[test]
fn test_felt_to_bigint() {
    let (felts, expected_bigints) = get_tested_felts_and_corresponding_bigints();
    let converted_bigints: Vec<BigInt> = felts.iter().map(|x| felt_to_bigint(*x)).collect();

    assert_eq!(converted_bigints, expected_bigints);
}

#[test]
fn test_bigint_to_felt() {
    let (expected_felts, bigints) = get_tested_felts_and_corresponding_bigints();
    // TODO(Adi, 10/12/2022): The conversion of the BigInt STARK prime to a StarkFelt should fail
    // once full-node have a field representation; add this test case.
    let converted_felts: Vec<StarkFelt> = bigints
        .iter()
        .map(|x| bigint_to_felt(x).expect("BigInt to StarkFelt conversion has failed."))
        .collect();

    assert_eq!(converted_felts, expected_felts);
}
