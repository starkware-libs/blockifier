use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use once_cell::sync::Lazy;
use serde::Deserialize;
use thiserror::Error;

const DEFAULT_CONSTANTS_JSON: &str = include_str!("../resources/versioned_constants.json");
static DEFAULT_CONSTANTS: Lazy<VersionedConstants> = Lazy::new(|| {
    serde_json::from_str(DEFAULT_CONSTANTS_JSON)
        .expect("Versioned constants JSON file is malformed")
});

/// Contains constants for the Blockifier that may vary between versions.
/// Additional constants in the JSON file, not used by Blockifier but included for transparency, are
/// automatically ignored during deserialization.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VersionedConstants {
    // Fee related.
    // TODO: Consider making this a struct, this will require change the way we access these
    // values.
    pub vm_resource_fee_cost: Arc<HashMap<String, f64>>,

    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
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

#[derive(Debug, Error)]
pub enum VersionedConstantsError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("JSON file cannot be serialized into VersionedConstants: {0}")]
    ParseError(#[from] serde_json::Error),
}
