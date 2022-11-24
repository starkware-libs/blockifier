use std::fs;
use std::process::Command;

use anyhow::{ensure, Context, Result};

const FEATURE_CONTRACTS_DIR: &str = "feature_contracts";
const COMPILED_CONTRACTS_SUBDIR: &str = "compiled";

// Checks that:
// 1. `TEST_CONTRACTS` dir exists and contains only `.cairo` files and the subdirectory
// `COMPILED_CONTRACTS_SUBDIR`.
// 2. for each `X.cairo` file in `TEST_CONTRACTS` there exists an `X_compiled.json` file in
// `COMPILED_CONTRACTS_SUBDIR` which equals `starknet-compile X.cairo -- -no_debug_info`.
fn verify_feature_contracts_compatibility(fix: bool) -> Result<()> {
    for file in fs::read_dir(FEATURE_CONTRACTS_DIR).unwrap() {
        let path = file.unwrap().path();

        // Test `TEST_CONTRACTS` file and directory structure.
        if !path.is_file() {
            if let Some(dir_name) = path.file_name() {
                ensure!(
                    dir_name == COMPILED_CONTRACTS_SUBDIR,
                    "Found directory '{}' in `{FEATURE_CONTRACTS_DIR}`, which should contain only \
                     the `{COMPILED_CONTRACTS_SUBDIR}` directory.",
                    dir_name.to_string_lossy()
                );
                continue;
            }
        }
        let path_str = path.to_string_lossy();
        ensure!(
            path.extension().unwrap() == "cairo",
            "Found a non-Cairo file '{path_str}' in `{FEATURE_CONTRACTS_DIR}`"
        );

        // Compare output of cairo-file on file with existing compiled file.
        let file_name = path.file_stem().unwrap().to_string_lossy();
        let existing_compiled_path = format!(
            "{FEATURE_CONTRACTS_DIR}/{COMPILED_CONTRACTS_SUBDIR}/{file_name}_compiled.json"
        );
        let mut command = Command::new("starknet-compile");
        command.args([&path_str, "--no_debug_info"]);
        if file_name.starts_with("account") {
            command.arg("--account_contract");
        }
        let expected_compiled_output = command.output().unwrap().stdout;

        if fix {
            fs::write(&existing_compiled_path, &expected_compiled_output)?;
        }
        let existing_compiled_contents = fs::read_to_string(&existing_compiled_path)
            .context(format!("Cannot read {existing_compiled_path}."))?;

        if String::from_utf8(expected_compiled_output).unwrap() != existing_compiled_contents {
            panic!("{} does not compile to {}", path_str, existing_compiled_path)
        }
    }
    Ok(())
}

#[test]
#[ignore]
fn verify_feature_contracts() -> Result<()> {
    verify_feature_contracts_compatibility(false)
}
