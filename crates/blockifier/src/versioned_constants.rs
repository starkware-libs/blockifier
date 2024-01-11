use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use once_cell::sync::Lazy;
use serde::Deserialize;
use starknet_api::core::ChainId;
use thiserror::Error;

const MAINNET_CONSTANTS_RAW: &str =
    include_str!("../resources/mainnet_constants/versioned_constants.json");
static DEFAULT_MAINNET_CONSTANTS: Lazy<VersionedConstants> =
    Lazy::new(|| serde_json::from_str(MAINNET_CONSTANTS_RAW).expect("malformed config.json"));

const SEPOLIA_CONSTANTS_RAW: &str =
    include_str!("../resources/sepolia_constants/versioned_constants.json");
static DEFAULT_SEPOLIA_CONSTANTS: Lazy<VersionedConstants> =
    Lazy::new(|| serde_json::from_str(SEPOLIA_CONSTANTS_RAW).expect("malformed config.json"));

#[derive(Clone, Debug, Default, Deserialize)]
pub struct VersionedConstants {
    // Fee related.
    pub vm_resource_fee_cost: Arc<HashMap<String, f64>>,

    // Limits.
    pub invoke_tx_max_n_steps: u32,
    pub validate_max_n_steps: u32,
    pub max_recursion_depth: usize,
}

impl VersionedConstants {
    pub fn latest_mainnet() -> &'static Self {
        &DEFAULT_MAINNET_CONSTANTS
    }

    pub fn latest_sepolia() -> &'static Self {
        &DEFAULT_SEPOLIA_CONSTANTS
    }
}

impl TryFrom<&Path> for VersionedConstants {
    type Error = VersionedConstantsError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let config_raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&config_raw)?)
    }
}

impl TryFrom<ChainId> for VersionedConstants {
    type Error = VersionedConstantsError;

    fn try_from(chain_id: ChainId) -> Result<Self, Self::Error> {
        let chain_id_name = chain_id.0.as_str();
        let constants = match chain_id_name {
            "SN_MAIN" | "" => DEFAULT_MAINNET_CONSTANTS.clone(),
            "SN_SEPOLIA" => DEFAULT_SEPOLIA_CONSTANTS.clone(),
            _ => {
                return Err(VersionedConstantsError::ChainIdNotSupported(
                    chain_id_name.to_string(),
                ));
            }
        };
        Ok(constants)
    }
}

#[derive(Debug, Error)]
pub enum VersionedConstantsError {
    #[error("JSON file cannot be serialized into VersionedConstants: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(
        "Unknown chain id: {0}. Please create A `VersionedConstants` from a custom json file."
    )]
    ChainIdNotSupported(String),
}
