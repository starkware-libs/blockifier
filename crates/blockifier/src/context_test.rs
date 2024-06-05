use std::fmt::Debug;
use std::fs::File;
use std::path::{Path, PathBuf};

use clap::Command;
use papyrus_config::dumping::SerializeConfig;
use papyrus_config::loading::load_and_process_config;
use serde::Deserialize;
use validator::Validate;

const TEST_FILES_FOLDER: &str = "./tests/config";
const FEE_TOKEN_ADDRESSES_CONFIG_FILE: &str = "fee_token_addresses.json";
const CHAIN_INFO_CONFIG_FILE: &str = "chain_info.json";

fn get_config_file_path(file_name: &str) -> PathBuf {
    Path::new(TEST_FILES_FOLDER).join(file_name)
}

fn get_config_from_file<T: for<'a> Deserialize<'a>>(
    file_path: PathBuf,
) -> Result<T, papyrus_config::ConfigError> {
    let config_file = File::open(file_path).unwrap();
    load_and_process_config(config_file, Command::new(""), vec![])
}

fn test_valid_config_body<
    T: for<'a> Deserialize<'a> + SerializeConfig + Validate + PartialEq + Debug,
>(
    expected_config: T,
    config_file_path: PathBuf,
    fix: bool,
) {
    if fix {
        expected_config.dump_to_file(&vec![], config_file_path.to_str().unwrap()).unwrap();
    }

    let loaded_config: T = get_config_from_file(config_file_path).unwrap();

    assert!(loaded_config.validate().is_ok());
    assert_eq!(loaded_config, expected_config);
}

#[test]
/// Read fee token addresses formatted as a papyrus config file and validate its content.
fn test_valid_fee_token_addresses_config() {
    let expected_config = crate::context::FeeTokenAddresses::create_for_testing();
    let file_path = get_config_file_path(FEE_TOKEN_ADDRESSES_CONFIG_FILE);
    let fix = false;
    test_valid_config_body(expected_config, file_path, fix);
}

#[test]
/// Read chain info formatted as a papyrus config file and validate its content.
fn test_valid_chain_info_config() {
    let expected_config = crate::context::ChainInfo::create_for_testing();
    let file_path = get_config_file_path(CHAIN_INFO_CONFIG_FILE);
    let fix = true;
    test_valid_config_body(expected_config, file_path, fix);
}
