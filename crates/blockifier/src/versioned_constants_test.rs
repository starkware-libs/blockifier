use cairo_vm::types::builtin_name::BuiltinName;
use glob::glob;
use pretty_assertions::assert_eq;

use super::*;

// TODO: Test Starknet OS validation.
// TODO: Add an unallowed field scenario for GasCost parsing.

#[test]
fn test_successful_gas_costs_parsing() {
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
        "error_out_of_gas": "An additional field in GasCosts::ADDITIONAL_ALLOWED_NAMES, ignored."
    }"#;
    let gas_costs = GasCosts::create_for_testing_from_subset(json_data);
    let os_constants: Arc<OsConstants> = Arc::new(OsConstants { gas_costs, ..Default::default() });
    let versioned_constants = VersionedConstants { os_constants, ..Default::default() };

    assert_eq!(versioned_constants.os_constants.gas_costs.step_gas_cost, 2);
    assert_eq!(versioned_constants.os_constants.gas_costs.entry_point_initial_budget, 2 * 3); // step_gas_cost * 3.

    // entry_point_initial_budget * 4 + step_gas_cost * 5.
    assert_eq!(versioned_constants.os_constants.gas_costs.entry_point_gas_cost, 6 * 4 + 2 * 5);
}

fn get_json_value_without_defaults() -> serde_json::Value {
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
    // Remove defaults from OsConstants.
    os_constants.as_object_mut().unwrap().remove("validate_rounding_consts");

    let mut json_value_without_defaults: Value = serde_json::from_str(json_data).unwrap();
    json_value_without_defaults
        .as_object_mut()
        .unwrap()
        .insert("os_constants".to_string(), os_constants);

    json_value_without_defaults
}

/// Assert `versioned_constants_base_overrides` are used when provided.
#[test]
fn test_versioned_constants_base_overrides() {
    // Create a versioned constants copy with a modified value for `invoke_tx_max_n_steps`.
    let mut versioned_constants_base_overrides = DEFAULT_CONSTANTS.clone();
    versioned_constants_base_overrides.invoke_tx_max_n_steps += 1;

    let result = VersionedConstants::get_versioned_constants(VersionedConstantsOverrides {
        validate_max_n_steps: versioned_constants_base_overrides.validate_max_n_steps,
        max_recursion_depth: versioned_constants_base_overrides.max_recursion_depth,
        versioned_constants_base_overrides: Some(versioned_constants_base_overrides.clone()),
    });

    // Assert the new value is used.
    assert_eq!(
        result.invoke_tx_max_n_steps,
        versioned_constants_base_overrides.invoke_tx_max_n_steps
    );
}

#[test]
fn test_default_values() {
    let json_value_without_defaults = get_json_value_without_defaults();

    let versioned_constants: VersionedConstants =
        serde_json::from_value(json_value_without_defaults).unwrap();

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
            (BuiltinName::pedersen, 16),
            (BuiltinName::range_check, 63),
        ]),
        ..Default::default()
    };
    assert_eq!(
        versioned_constants.os_resources_for_tx_type(&TransactionType::Declare, calldata_length),
        expected_declare_resources
    );
    // The default value of disabled_cairo0_redeclaration is false to allow backward compatibility.
    assert_eq!(versioned_constants.disable_cairo0_redeclaration, false);
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

    let error = serde_json::from_str::<OsConstants>(json_data).unwrap_err();
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

#[test]
fn test_old_json_parsing() {
    let files = glob(format!("{}/resources/*.json", env!("CARGO_MANIFEST_DIR")).as_str()).unwrap();
    for file in files.map(Result::unwrap) {
        serde_json::from_reader::<_, VersionedConstants>(&std::fs::File::open(&file).unwrap())
            .unwrap_or_else(|_| panic!("Versioned constants JSON file {file:#?} is malformed"));
    }
}
