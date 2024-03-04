use pretty_assertions::assert_eq;

use super::*;
use crate::test_utils::update_json_value;

// TODO: Test Starknet OS validation.

impl OSConstants {
    fn create_for_testing(subset_of_os_constants: &str) -> OSConstants {
        let subset_of_os_constants: Value = serde_json::from_str(subset_of_os_constants).unwrap();
        let default_versioned_constants: Value =
            serde_json::from_str(DEFAULT_CONSTANTS_JSON).unwrap();
        let mut os_constants: Value =
            default_versioned_constants.get("os_constants").unwrap().clone();
        update_json_value(&mut os_constants, subset_of_os_constants);
        let os_constants: OSConstants = serde_json::from_value(os_constants).unwrap();
        os_constants
    }
}

#[test]
fn test_successful_parsing() {
    let json_data = r#"
    {
        "step_gas_cost": 2,
        "entry_point_initial_budget": {
            "step_gas_cost": 3
        },
        "entry_point_gas_cost": {
            "entry_point_initial_budget": 4,
            "step_gas_cost": 5
        },
        "validate_block_number_rounding": 111,
        "validate_timestamp_rounding": 222,
        "ignore the gas string": "GAS!",
        "I look like a gas cost but my name is all wrong": 0
    }"#;
    let os_constants: Arc<OSConstants> = Arc::new(OSConstants::create_for_testing(json_data));
    let versioned_constants = VersionedConstants { os_constants, ..Default::default() };

    assert_eq!(versioned_constants.gas_cost("step_gas_cost"), 2);
    assert_eq!(versioned_constants.gas_cost("entry_point_initial_budget"), 2 * 3); // step_gas_cost * 3.

    // entry_point_intial_budget * 4 + step_gas_cost * 5.
    assert_eq!(versioned_constants.gas_cost("entry_point_gas_cost"), 6 * 4 + 2 * 5);

    assert_eq!(
        versioned_constants.os_constants.gas_costs.len(),
        OSConstants::ALLOWED_GAS_COST_NAMES.len()
    );
}

fn get_json_value_without_dafaults() -> serde_json::Value {
    let json_data = r#"
    {
        "invoke_tx_max_n_steps": 2,
        "validate_max_n_steps": 1,
        "os_constants": {},
        "os_resources": {
            "execute_syscalls":{},
            "execute_txs_inner": {
                "Declare": {
                    "deprecated_resources":{
                        "builtin_instance_counter": {
                            "pedersen_builtin": 16,
                            "range_check_builtin": 63
                        },
                        "n_memory_holes": 0,
                        "n_steps": 2839
                    },
                    "resources": {
                        "builtin_instance_counter": {
                            "pedersen_builtin": 16,
                            "range_check_builtin": 63
                        },
                        "n_memory_holes": 0,
                        "n_steps": 2839
                    }
                }
            },
            "compute_os_kzg_commitment_info": {
                "builtin_instance_counter": {},
                "n_memory_holes": 1,
                "n_steps": 2
            }
        },
        "vm_resource_fee_cost": {},
        "max_recursion_depth": 2
    }"#;
    let mut json_data_without_dafualts: Value =
        serde_json::from_str(json_data).expect("The input data must be a vaild json.");
    let default_versioned_constants: Value = serde_json::from_str(DEFAULT_CONSTANTS_JSON)
        .expect("The default versioned constants must be a valid json.");
    let mut os_constants: Value = default_versioned_constants
        .get("os_constants")
        .expect("The default versioned constants should contain os_constants.")
        .clone();

    if let Some(obj) = os_constants.as_object_mut() {
        obj.remove("validate_rounding_consts");
    }

    if let Value::Object(ref mut obj) = json_data_without_dafualts {
        obj.insert("os_constants".to_string(), os_constants);
    }

    json_data_without_dafualts
}

#[test]
fn test_default_values() {
    let json_data_without_dafualts = get_json_value_without_dafaults();

    let versioned_constants: VersionedConstants =
        serde_json::from_value(json_data_without_dafualts).unwrap();

    assert_eq!(versioned_constants.get_validate_block_number_rounding(), 1);
    assert_eq!(versioned_constants.get_validate_timestamp_rounding(), 1);

    assert_eq!(versioned_constants.tx_event_limits, EventLimits::max());
    assert_eq!(versioned_constants.l2_resource_gas_costs, L2ResourceGasCosts::default());

    // Calldata factor was initialized as 0, and did not affect the expected result, even if
    // calldata length is nonzero.
    let calldata_length = 2;
    let expected_declare_resources = ExecutionResources {
        n_steps: 2839,
        builtin_instance_counter: HashMap::from([
            ("pedersen_builtin".to_string(), 16),
            ("range_check_builtin".to_string(), 63),
        ]),
        ..Default::default()
    };
    assert_eq!(
        versioned_constants.os_resources_for_tx_type(&TransactionType::Declare, calldata_length),
        expected_declare_resources
    );
}

#[test]
fn test_string_inside_composed_field() {
    let json_data = r#"
    {
        "step_gas_cost": 2,
        "entry_point_initial_budget": {
            "step_gas_cost": "meow"
        }
    }"#;

    check_constants_serde_error(
        json_data,
        "Value \"meow\" used to create value for key 'entry_point_initial_budget' is out of range \
         and cannot be cast into u64",
    );
}

fn check_constants_serde_error(json_data: &str, expected_error_message: &str) {
    let mut json_data_raw: IndexMap<String, Value> = serde_json::from_str(json_data).unwrap();
    json_data_raw.insert("validate_block_number_rounding".to_string(), 0.into());
    json_data_raw.insert("validate_timestamp_rounding".to_string(), 0.into());

    let json_data = &serde_json::to_string(&json_data_raw).unwrap();

    let error = serde_json::from_str::<OSConstants>(json_data).unwrap_err();
    assert_eq!(error.to_string(), expected_error_message);
}

#[test]
fn test_missing_key() {
    let json_data = r#"
    {
        "entry_point_initial_budget": {
            "TEN LI GAZ!": 2
        }
    }"#;
    check_constants_serde_error(
        json_data,
        "Unknown key 'TEN LI GAZ!' used to create value for 'entry_point_initial_budget'",
    );
}

#[test]
fn test_unhandled_value_type() {
    let json_data = r#"
    {
        "step_gas_cost": []
    }"#;
    check_constants_serde_error(json_data, "Unhandled value type: []");
}

#[test]
fn test_invalid_number() {
    check_constants_serde_error(
        r#"{"step_gas_cost": 42.5}"#,
        "Value 42.5 for key 'step_gas_cost' is out of range and cannot be cast into u64",
    );

    check_constants_serde_error(
        r#"{"step_gas_cost": -2}"#,
        "Value -2 for key 'step_gas_cost' is out of range and cannot be cast into u64",
    );

    let json_data = r#"
    {
        "step_gas_cost": 2,
        "entry_point_initial_budget": {
            "step_gas_cost": 42.5
        }
    }"#;
    check_constants_serde_error(
        json_data,
        "Value 42.5 used to create value for key 'entry_point_initial_budget' is out of range and \
         cannot be cast into u64",
    );
}
