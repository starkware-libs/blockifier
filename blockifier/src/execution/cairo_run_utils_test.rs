use std::fs::File;
use std::io::BufReader;

use anyhow::{bail, Result};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use starknet_api::StarkFelt;

use crate::execution::cairo_run_utils::felt_to_bigint;

fn _get_stark_felt() -> Result<StarkFelt> {
    let test_contract = "simple_contract_compiled.json";
    let test_contract_file = File::open(format!("./feature_contracts/compiled/{test_contract}"))?;
    let reader = BufReader::new(test_contract_file);

    if let serde_json::Value::Object(contract_object) = serde_json::from_reader(reader)? {
        if let serde_json::Value::Object(program) = &contract_object["program"] {
            if let serde_json::Value::String(stark_felt) = &program["prime"] {
                return Ok(StarkFelt::from_hex(stark_felt)
                    .expect("The conversion of STARK prime to `StarkFelt` has failed."));
            }
        }
    }
    bail!("Reading the STARK prime from `{test_contract}` has failed.")
}

#[test]
fn test_felt_to_bigint() -> Result<()> {
    let stark_prime = _get_stark_felt()?;
    let felts = vec![
        // TODO(Adi, 29/11/2022): Remove the 'StarkFelt::from_u64' conversions once there is a
        // From<u64> trait for StarkFelt.
        StarkFelt::from_u64(0),
        StarkFelt::from_u64(1),
        stark_prime,
    ];
    let expected_bigints: Vec<BigInt> = vec![
        Zero::zero(),
        One::one(),
        // The STARK prime is 2 ^ 251 + 17 * 2 ^ 192 + 1.
        BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
    ];
    let converted_bigints: Vec<BigInt> = felts.iter().map(|x| felt_to_bigint(*x)).collect();

    assert_eq!(converted_bigints, expected_bigints);
    Ok(())
}
