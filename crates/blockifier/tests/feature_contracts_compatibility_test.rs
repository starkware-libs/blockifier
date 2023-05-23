use std::fs;
use std::process::Command;

const FEATURE_CONTRACTS_DIR: &str = "feature_contracts/cairo0";
const COMPILED_CONTRACTS_SUBDIR: &str = "compiled";
const FIX_COMMAND: &str = "FIX_FEATURE_TEST=1 cargo test -- --ignored";

// To fix feature contracts, first enter a python venv and install the requirements:
// ```
// python -m venv tmp_venv
// . tmp_venv/bin/activate
// pip install -r crates/blockifier/tests/requirements.txt
// ```
// Then, run the FIX_COMMAND above.

// Checks that:
// 1. `TEST_CONTRACTS` dir exists and contains only `.cairo` files and the subdirectory
// `COMPILED_CONTRACTS_SUBDIR`.
// 2. for each `X.cairo` file in `TEST_CONTRACTS` there exists an `X_compiled.json` file in
// `COMPILED_CONTRACTS_SUBDIR` which equals `starknet-compile X.cairo -- -no_debug_info`.
fn verify_feature_contracts_compatibility(fix: bool) {
    for file in fs::read_dir(FEATURE_CONTRACTS_DIR).unwrap() {
        let path = file.unwrap().path();

        // Test `TEST_CONTRACTS` file and directory structure.
        if !path.is_file() {
            if let Some(dir_name) = path.file_name() {
                assert_eq!(
                    dir_name,
                    COMPILED_CONTRACTS_SUBDIR,
                    "Found directory '{}' in `{FEATURE_CONTRACTS_DIR}`, which should contain only \
                     the `{COMPILED_CONTRACTS_SUBDIR}` directory.",
                    dir_name.to_string_lossy()
                );
                continue;
            }
        }
        let path_str = path.to_string_lossy();
        assert_eq!(
            path.extension().unwrap(),
            "cairo",
            "Found a non-Cairo file '{path_str}' in `{FEATURE_CONTRACTS_DIR}`"
        );

        // Compare output of cairo-file on file with existing compiled file.
        let file_name = path.file_stem().unwrap().to_string_lossy();
        let existing_compiled_path = format!(
            "{FEATURE_CONTRACTS_DIR}/{COMPILED_CONTRACTS_SUBDIR}/{file_name}_compiled.json"
        );
        let mut command = Command::new("starknet-compile-deprecated");
        command.args([&path_str, "--no_debug_info"]);
        if file_name.starts_with("account") {
            command.arg("--account_contract");
        }
        if file_name.starts_with("security") {
            command.arg("--disable_hint_validation");
        }
        let compile_output = command.output().unwrap();
        let stderr_output = String::from_utf8(compile_output.stderr).unwrap();
        assert!(compile_output.status.success(), "{stderr_output}");
        let expected_compiled_output = compile_output.stdout;

        if fix {
            fs::write(&existing_compiled_path, &expected_compiled_output).unwrap();
        }
        let existing_compiled_contents = fs::read_to_string(&existing_compiled_path)
            .unwrap_or_else(|_| panic!("Cannot read {existing_compiled_path}."));

        if String::from_utf8(expected_compiled_output).unwrap() != existing_compiled_contents {
            panic!(
                "{path_str} does not compile to {existing_compiled_path}.\nRun `{FIX_COMMAND}` to \
                 fix the expected test according to locally installed \
                 `starknet-compile-deprecated`.\n"
            );
        }
    }
}

#[test]
#[ignore]
fn verify_feature_contracts() {
    let fix_features = std::env::var("FIX_FEATURE_TEST").is_ok();
    verify_feature_contracts_compatibility(fix_features)
}
