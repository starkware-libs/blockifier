use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use starknet_api::StarkFelt;

use crate::execution::cairo_run_utils::bigint_to_felt;

// The STARK prime is 2 ^ 251 + 17 * 2 ^ 192 + 1.
const STARK_PRIME: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
const STARK_PRIME_MINUS_ONE: &str =
    "0x800000000000011000000000000000000000000000000000000000000000000";

fn get_tested_felts_and_corresponding_bigints() -> (Vec<StarkFelt>, Vec<BigInt>) {
    let felt_from_hex_error_message = "`StarkFelt` construction from hex has failed.";
    let felts = vec![
        // TODO(Adi, 29/11/2022): Remove the 'StarkFelt::from_u64' conversions once there is a
        // From<u64> trait for StarkFelt.
        StarkFelt::from_u64(0),
        StarkFelt::from_u64(1),
        StarkFelt::from_u64(1234),
        StarkFelt::from_hex(STARK_PRIME).expect(felt_from_hex_error_message),
        StarkFelt::from_hex(STARK_PRIME_MINUS_ONE).expect(felt_from_hex_error_message),
    ];
    let bigints = vec![
        Zero::zero(),
        One::one(),
        BigInt::new(Sign::Plus, vec![1234]),
        // This prime constant is taken from examples in the cairo-rs crate.
        // Note: the BigInt digits are ordered least significant digit first.
        BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        BigInt::new(Sign::Plus, vec![0, 0, 0, 0, 0, 0, 17, 134217728]),
    ];

    (felts, bigints)
}

#[test]
fn test_bigint_to_felt() {
    let (expected_felts, bigints) = get_tested_felts_and_corresponding_bigints();
    let converted_felts: Vec<StarkFelt> = bigints
        .iter()
        .map(|x| bigint_to_felt(x).expect("BigInt to StarkFelt conversion has failed."))
        .collect();

    assert_eq!(converted_felts, expected_felts);
}
