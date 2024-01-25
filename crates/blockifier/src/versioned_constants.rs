use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use indexmap::IndexMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use thiserror::Error;

#[cfg(test)]
#[path = "versioned_constants_test.rs"]
pub mod test;

const DEFAULT_CONSTANTS_JSON: &str = include_str!("../resources/versioned_constants.json");
static DEFAULT_CONSTANTS: Lazy<VersionedConstants> = Lazy::new(|| {
    serde_json::from_str(DEFAULT_CONSTANTS_JSON)
        .expect("Versioned constants json file is malformed")
});

/// `VersionedConstants` contains constants for the Blockifier that may vary between versions.
/// Additional constants in the JSON file, not used by Blockifier but included for transparency, are
/// automatically ignored during deserialization.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VersionedConstants {
    // Fee related.
    pub vm_resource_fee_cost: Arc<HashMap<String, f64>>,

    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,

    // Cairo OS constants.
    // Note: if loaded from a json file, there are some assumptions made on its structure.
    // See the struct's docstring for more details.
    pub cairo_os_constants: CairoOSConstants,
}

impl VersionedConstants {
    /// Get the constants that shipped with the current version of the Blockifier.
    /// To use custom constants, initialize the struct from a file using `try_from`.
    pub fn latest_constants() -> &'static Self {
        &DEFAULT_CONSTANTS
    }
}

impl TryFrom<&Path> for VersionedConstants {
    type Error = VersionedConstantsError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
    }
}

// Below, serde first deserializes the json into a regular IndexMap wrapped by the newtype
// `CairoOSConstantsRawJSON`, then calls the `try_from` of the newtype, which handles the conversion
// into actual values.
// Assumption: if the json has a value that contains the expression "FOO * 2", then the key `FOO`
// must appear before this value in the JSON.
// TODO: JSON doesn't guarantee order, but implementation does; consider using a different format
// than JSON to prevent misunderstandings.
// TODO: consider encoding the * and + operations inside the
// json file, instead of hardcoded below in the `try_from`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(try_from = "CairoOSConstantsRawJSON")]
pub struct CairoOSConstants {
    integer_constants: IndexMap<String, i64>,
    string_constants: IndexMap<String, String>,
}

impl TryFrom<CairoOSConstantsRawJSON> for CairoOSConstants {
    type Error = CairoConstantsSerdeError;

    fn try_from(intermediate: CairoOSConstantsRawJSON) -> Result<Self, Self::Error> {
        let mut integer_constants = IndexMap::new();
        let mut string_constants = IndexMap::new();

        for (key, value) in intermediate.regular {
            match value {
                Value::String(s) => {
                    string_constants.insert(key, s);
                }
                Value::Number(n) => {
                    let value =
                        n.as_i64().ok_or(CairoConstantsSerdeError::InvalidNumberFormat(n))?;
                    integer_constants.insert(key, value);
                }
                Value::Object(obj) => {
                    // Convert the `KEY: value` pairs into a sum of `value *
                    // integer_constants[KEY]` for every `KEY`.
                    // Assumption: keys are ordered so that each key lookup is successful.
                    let sum = obj.into_iter().try_fold(0, |acc, (inner_key, factor)| {
                        let factor = factor
                            .as_i64()
                            .ok_or(CairoConstantsSerdeError::InvalidFactorFormat(factor))?;
                        let field_value = *integer_constants
                            .get(&inner_key)
                            .ok_or(CairoConstantsSerdeError::KeyNotFound(inner_key))?;

                        Ok(acc + field_value * factor)
                    })?;
                    integer_constants.insert(key, sum);
                }
                _ => return Err(CairoConstantsSerdeError::UnhandledValueType(value)),
            }
        }

        Ok(CairoOSConstants { integer_constants, string_constants })
    }
}

// Intermediate representation of the JSON file in order to make the deserialization easier, using a
// regular the try_from.
#[derive(Debug, Deserialize)]
struct CairoOSConstantsRawJSON {
    #[serde(flatten)]
    regular: IndexMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum VersionedConstantsError {
    #[error("JSON file cannot be serialized into VersionedConstants: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum CairoConstantsSerdeError {
    #[error("Number cannot be cast into i64: {0}")]
    InvalidNumberFormat(Number),
    #[error("Key not found in fields: {0}")]
    KeyNotFound(String),
    #[error("Value cannot be cast into i64: {0}")]
    InvalidFactorFormat(Value),
    #[error("Unhandled value type: {0}")]
    UnhandledValueType(Value),
}
