use std::fs;
use std::process::Command;

use pretty_assertions::assert_eq;

const TEST_CONTRACTS_DIR: &str = "test_contracts";
const COMPILED_CONTRACTS_SUBDIR: &str = "compiled";
const COMPILED_CONTRACTS_PATH: &str = "test_contracts/compiled";

// Checks that:
// 1) `TEST_CONTRACTS` dir exists and contains only `.cairo` files and the subdirectory
// `COMPILED_CONTRACTS_SUBDIR`.
// 2) for each `X.cairo` file in `TEST_CONTRACTS` there exists an `X.json` file in
// `COMPILED_CONTRACTS_SUBDIR` which equals `cairo-compile X.cairo -- -no_debug_info`.
#[test]
#[ignore]
fn compiled_files_compatibility() -> Result<(), String> {
    for file in fs::read_dir(TEST_CONTRACTS_DIR).unwrap() {
        let path = file.unwrap().path();

        // Test `TEST_CONTRACTS` file and directory structure.
        if !path.is_file() {
            match path.file_name() {
                Some(dir_name) if dir_name == COMPILED_CONTRACTS_SUBDIR => continue,
                Some(dir_name) => {
                    return Err(format!(
                        "Found directory '{}' in `{TEST_CONTRACTS_DIR}`, which should contain \
                         only the `{COMPILED_CONTRACTS_SUBDIR}` directory.",
                        dir_name.to_string_lossy()
                    ));
                }
                None => return Err("IO error".to_string()),
            }
        }
        let path_str = path.to_str().unwrap();
        if path.extension().unwrap() != "cairo" {
            return Err(format!("Found a non-Cairo file '{}' in `{TEST_CONTRACTS_DIR}`", path_str));
        }

        // Compare output of cairo-file on file with existing compiled file.
        let file_name = path.file_stem().unwrap().to_string_lossy();
        let existing_compiled_path = format!("{COMPILED_CONTRACTS_PATH}/{file_name}.json");
        let existing_compiled_contents = match fs::read_to_string(&existing_compiled_path) {
            Ok(json_contents) => json_contents,
            Err(_) => return Err(format!("Cannot read {}.", existing_compiled_path)),
        };

        let expected_compiled_output = Command::new("cairo-compile")
            .args([path_str, "--no_debug_info"])
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
