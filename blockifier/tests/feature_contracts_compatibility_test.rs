use std::fs;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use pretty_assertions::assert_eq;

const FEATURE_CONTRACTS_DIR: &str = "feature_contracts";
const COMPILED_CONTRACTS_SUBDIR: &str = "compiled";

// Checks that:
// 1. `TEST_CONTRACTS` dir exists and contains only `.cairo` files and the subdirectory
// `COMPILED_CONTRACTS_SUBDIR`.
// 2. for each `X.cairo` file in `TEST_CONTRACTS` there exists an `X.json` file in
// `COMPILED_CONTRACTS_SUBDIR` which equals `cairo-compile X.cairo -- -no_debug_info`.
#[test]
#[ignore]
fn verify_feature_contracts_compatibility() -> Result<()> {
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
        let existing_compiled_path =
            format!("{FEATURE_CONTRACTS_DIR}/{COMPILED_CONTRACTS_SUBDIR}/{file_name}.json");
        let existing_compiled_contents = fs::read_to_string(&existing_compiled_path)
            .context(format!("Cannot read {existing_compiled_path}."))?;
        let expected_compiled_output = Command::new("cairo-compile")
            .args([&path_str, "--no_debug_info"])
            .output()
            .unwrap()
            .stdout;

        assert_eq!(
            String::from_utf8(expected_compiled_output).unwrap(),
            existing_compiled_contents
        );
    }
    Ok(())
}
