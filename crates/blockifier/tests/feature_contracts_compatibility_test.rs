use std::fs;

use blockifier::test_utils::cairo_compile::cairo1_compiler_tag;
use blockifier::test_utils::contracts::{FeatureContract, LEGACY_CONTRACT_COMPILER_TAG};
use blockifier::test_utils::CairoVersion;
use pretty_assertions::assert_eq;
use rstest::rstest;

const CAIRO0_FEATURE_CONTRACTS_DIR: &str = "feature_contracts/cairo0";
const CAIRO1_FEATURE_CONTRACTS_DIR: &str = "feature_contracts/cairo1";
const COMPILED_CONTRACTS_SUBDIR: &str = "compiled";
const FIX_COMMAND: &str = "FIX_FEATURE_TEST=1 cargo test -- --ignored";

// To fix Cairo0 feature contracts, first enter a python venv and install the requirements:
// ```
// python -m venv tmp_venv
// . tmp_venv/bin/activate
// pip install -r crates/blockifier/tests/requirements.txt
// ```
// Then, run the FIX_COMMAND above.

// To test Cairo1 feature contracts, first clone the Cairo repo and checkout the required tag.
// The repo should be located next to the blockifier repo:
// <WORKSPACE_DIR>/
// - blockifier/
// - cairo/
// Then, run the FIX_COMMAND above.

// Checks that:
// 1. `TEST_CONTRACTS` dir exists and contains only `.cairo` files and the subdirectory
// `COMPILED_CONTRACTS_SUBDIR`.
// 2. for each `X.cairo` file in `TEST_CONTRACTS` there exists an `X_compiled.json` file in
// `COMPILED_CONTRACTS_SUBDIR` which equals `starknet-compile-deprecated X.cairo --no_debug_info`.
fn verify_feature_contracts_compatibility(
    fix: bool,
    contracts_to_test: impl Iterator<Item = FeatureContract>,
) {
    for contract in contracts_to_test {
        // Compare output of cairo-file on file with existing compiled file.
        let expected_compiled_output = contract.compile();
        let existing_compiled_path = contract.get_compiled_path();

        if fix {
            fs::write(&existing_compiled_path, &expected_compiled_output).unwrap();
        }
        let existing_compiled_contents = fs::read_to_string(&existing_compiled_path)
            .unwrap_or_else(|_| panic!("Cannot read {existing_compiled_path}."));

        if String::from_utf8(expected_compiled_output).unwrap() != existing_compiled_contents {
            panic!(
                "{} does not compile to {existing_compiled_path}.\nRun `{FIX_COMMAND}` to fix the \
                 expected test according to locally installed `starknet-compile-deprecated`.\n",
                contract.get_source_path()
            );
        }
    }
}

/// Verifies that the feature contracts directory contains the expected contents, and returns a list
/// of pairs (source_path, base_filename, compiled_path) for each contract.
fn verify_and_get_files(cairo_version: CairoVersion) -> Vec<(String, String, String)> {
    let mut paths = vec![];
    let directory = match cairo_version {
        CairoVersion::Cairo0 => CAIRO0_FEATURE_CONTRACTS_DIR,
        CairoVersion::Cairo1 => CAIRO1_FEATURE_CONTRACTS_DIR,
    };
    let compiled_extension = match cairo_version {
        CairoVersion::Cairo0 => "_compiled.json",
        CairoVersion::Cairo1 => ".casm.json",
    };
    for file in fs::read_dir(directory).unwrap() {
        let path = file.unwrap().path();

        // Verify `TEST_CONTRACTS` file and directory structure.
        if !path.is_file() {
            if let Some(dir_name) = path.file_name() {
                assert_eq!(
                    dir_name,
                    COMPILED_CONTRACTS_SUBDIR,
                    "Found directory '{}' in `{directory}`, which should contain only the \
                     `{COMPILED_CONTRACTS_SUBDIR}` directory.",
                    dir_name.to_string_lossy()
                );
                continue;
            }
        }
        let path_str = path.to_string_lossy();
        assert_eq!(
            path.extension().unwrap(),
            "cairo",
            "Found a non-Cairo file '{path_str}' in `{directory}`"
        );

        let file_name = path.file_stem().unwrap().to_string_lossy();
        let existing_compiled_path =
            format!("{directory}/{COMPILED_CONTRACTS_SUBDIR}/{file_name}{compiled_extension}");

        paths.push((path_str.to_string(), file_name.to_string(), existing_compiled_path));
    }

    paths
}

#[test]
fn test_cairo1_compiler_version_ci_files() {
    // For all except the legacy contract.
    let on_file = include_str!("cairo1_compiler_tag.txt").trim().to_string();
    assert_eq!(on_file, cairo1_compiler_tag());
    // Legacy contract
    let on_file = include_str!("legacy_cairo1_compiler_tag.txt").trim().to_string();
    assert_eq!(on_file, LEGACY_CONTRACT_COMPILER_TAG);
}

#[test]
fn verify_feature_contracts_match_enum() {
    let mut compiled_paths_from_enum: Vec<String> = FeatureContract::all_feature_contracts()
        .map(|contract| contract.get_compiled_path())
        .collect();
    let mut compiled_paths_on_filesystem: Vec<String> = verify_and_get_files(CairoVersion::Cairo0)
        .into_iter()
        .chain(verify_and_get_files(CairoVersion::Cairo1))
        .map(|(_, _, compiled_path)| compiled_path)
        .collect();
    compiled_paths_from_enum.sort();
    compiled_paths_on_filesystem.sort();
    assert_eq!(compiled_paths_from_enum, compiled_paths_on_filesystem);
}

fn is_env_var_set(env_var: &str) -> bool {
    std::env::var(env_var).is_ok()
}

#[rstest]
#[ignore]
fn verify_feature_contracts(
    #[values(CairoVersion::Cairo0, CairoVersion::Cairo1)] cairo_version: CairoVersion,
) {
    let fix_features = is_env_var_set("FIX_FEATURE_TEST");
    let legacy_mode = is_env_var_set("LEGACY");
    let ci_mode = is_env_var_set("CI");

    let contracts_to_test = FeatureContract::all_feature_contracts().filter(|contract| {
        // If called with LEGACY environment variable set, only test legacy contracts (from CI
        // or not).
        // If tested from the CI *without* the LEGACY environment variable set, test only
        // non-legacy contracts of the respective cairo version.
        // If not tested from CI, test all contracts of the requested cairo version.
        contract.cairo_version() == cairo_version
            && (if legacy_mode { contract.is_legacy() } else { !ci_mode || !contract.is_legacy() })
    });

    verify_feature_contracts_compatibility(fix_features, contracts_to_test)
}
