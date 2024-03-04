use pretty_assertions::assert_eq;

use super::*;

// TODO: Test Starknet OS validation.
// TODO: Add an unallowed field scenario for GasCost parsing.

#[test]
fn test_successful_gas_constants_parsing() {
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
        "error_out_of_gas": "An additional field in GasCosts::ADDITIONAL_ALLOWED_NAMES, ignored.",
        "validate_block_number_rounding": 111,
        "validate_timestamp_rounding": 222,
        "l2_gas_index": "An additional field in GasCosts::ADDITIONAL_ALLOWED_NAMES, to ignore.",
        "nop_entry_point_offset": "Another additional field in GasCosts::ADDITIONAL_ALLOWED_NAMES."
    }"#;
    let os_constants: Arc<OSConstants> =
        Arc::new(OSConstants::create_for_testing_from_subset(json_data));
    let versioned_constants = VersionedConstants { os_constants, ..Default::default() };

    assert_eq!(versioned_constants.os_constants.gas_costs.step_gas_cost, 2);
    assert_eq!(versioned_constants.os_constants.gas_costs.entry_point_initial_budget, 2 * 3); // step_gas_cost * 3.

    // entry_point_intial_budget * 4 + step_gas_cost * 5.
    assert_eq!(versioned_constants.os_constants.gas_costs.entry_point_gas_cost, 6 * 4 + 2 * 5);
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
    // Fill the os constants with the gas cost values (do not have a default value).
    let mut os_constants: Value = serde_json::from_str::<Value>(DEFAULT_CONSTANTS_JSON)
        .unwrap()
        .get("os_constants")
        .unwrap()
        .clone();
    // Remove defaults from OSConstants.
    os_constants.as_object_mut().unwrap().remove("validate_rounding_consts");

    let mut json_value_without_defualts: Value = serde_json::from_str(json_data).unwrap();
    json_value_without_defualts
        .as_object_mut()
        .unwrap()
        .insert("os_constants".to_string(), os_constants);

    json_value_without_defualts
}

#[test]
fn test_default_values() {
    let json_value_without_defualts = get_json_value_without_dafaults();

    let versioned_constants: VersionedConstants =
        serde_json::from_value(json_value_without_defualts).unwrap();

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
