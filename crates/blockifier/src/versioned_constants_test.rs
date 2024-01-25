use pretty_assertions::assert_eq;

use super::*;

#[test]
fn test_successful_parsing() {
    let json_data = r#"
    {
        "NUMBER1": -2,
        "STRING": "Test",
        "NUMBER2": 3,
        "COMPOSED1": {
            "NUMBER1": 3
        },
        "COMPOSED2": {
            "COMPOSED1": 4,
            "NUMBER2": 5
        }
    }"#;
    let result: CairoOSConstants = serde_json::from_str(json_data).unwrap();

    assert_eq!(result.integer_constants.get("NUMBER1"), Some(&-2));
    assert_eq!(result.string_constants.get("STRING"), Some(&"Test".to_string()));
    assert_eq!(result.integer_constants.get("NUMBER2"), Some(&3));
    assert_eq!(result.integer_constants.get("COMPOSED1"), Some(&-6)); // NUMBER1*3 == -2 * 3.
    assert_eq!(result.integer_constants.get("COMPOSED2"), Some(&-9)); // COMPOSED1*4 + NUMBER2*5 == -6*4 + 3*5.
}

#[test]
fn test_string_inside_composed_field() {
    let json_data = r#"
    {
        "NOT_A_NUMBER": "3xyz",
        "COMPOSED": {
            "NOT_A_NUMBER": 2
        }
    }"#;
    let expected_error_message = "Key not found in fields: NOT_A_NUMBER";

    let result = serde_json::from_str::<CairoOSConstants>(json_data).unwrap_err();
    assert_eq!(result.to_string(), expected_error_message);
}

#[test]
fn test_missing_key() {
    let json_data = r#"
    {
        "COMPOSED": {
            "MISSING_KEY": 3
        }
    }"#;
    let expected_error_message = "Key not found in fields: MISSING_KEY";

    let result = serde_json::from_str::<CairoOSConstants>(json_data).unwrap_err();
    assert_eq!(result.to_string(), expected_error_message);
}

#[test]
fn test_unhandled_value_type() {
    let json_data = r#"
    {
        "UNHANDLED_TYPE": []
    }"#;
    let expected_error_message = "Unhandled value type: []";

    let result = serde_json::from_str::<CairoOSConstants>(json_data).unwrap_err();
    assert_eq!(result.to_string(), expected_error_message);
}

#[test]
fn test_invalid_number() {
    let json_data = r#"
    {
        "not_an_int": 42.5 
    }"#;
    let expected_error_message = "Number cannot be cast into i64: 42.5";

    let result = serde_json::from_str::<CairoOSConstants>(json_data).unwrap_err();
    assert_eq!(result.to_string(), expected_error_message);
}

#[test]
fn test_invalid_factor() {
    let json_data = r#"
    {
        "not_an_int": 42.5 
    }"#;
    let expected_error_message = "Number cannot be cast into i64: 42.5";

    let result = serde_json::from_str::<CairoOSConstants>(json_data).unwrap_err();
    assert_eq!(result.to_string(), expected_error_message);
}
