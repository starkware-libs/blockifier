use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{env, fs};

use pretty_assertions::assert_eq;
use serde_json::Value;
use tempfile::NamedTempFile;

const COMPILED_CONTRACTS_SUBDIR: &str = "compiled";
const FIX_COMMAND: &str = "FIX_FEATURE_TEST=1 cargo test -- --ignored";

trait FeatureContracts {
    /// Verify that cairo files are compiled to the expected output, fix them if `fix` is true.
    fn verify(&self, fix: bool) {
        self.check_deps();
        for cairo_file in self.cairo_files() {
            println!("Verifying {cairo_file:?}.");

            let path_str = cairo_file.to_string_lossy();
            let file_name = cairo_file.file_stem().unwrap().to_string_lossy().to_string();

            let compiled_output = self.compile(&path_str, &file_name);
            self.compare(&path_str, &file_name, compiled_output, fix);
            println!("Success.");
        }
    }

    /// Return a list of all the cairo files in the contracts directory.
    /// Panic if there are non-cairo files or any directories besides the contracts directory.
    fn cairo_files(&self) -> Vec<PathBuf> {
        let contracts_dir = self.contracts_directory();

        fs::read_dir(contracts_dir)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    assert_eq!(
                        path.file_name().unwrap(),
                        COMPILED_CONTRACTS_SUBDIR,
                        "Found directory '{}' in `{contracts_dir}`, which should contain only the \
                         `{COMPILED_CONTRACTS_SUBDIR}` directory.",
                        path.to_string_lossy(),
                    );
                    None
                } else {
                    assert_eq!(
                        path.extension().unwrap(),
                        "cairo",
                        "Non-Cairo file '{}' found in '{contracts_dir}'.",
                        path.to_string_lossy(),
                    );
                    Some(path)
                }
            })
            .collect()
    }

    /// Check that the required dependencies are installed in order to compile the cairo files.
    fn check_deps(&self);

    fn compile(&self, path_str: &str, file_name: &str) -> Output;

    /// Compare the compiled output to the expected output.
    fn compare(&self, path_str: &str, file_name: &str, compile_output: Output, fix: bool) {
        let existing_compiled_path = format!(
            "{0}/{COMPILED_CONTRACTS_SUBDIR}/{file_name}{1}",
            self.contracts_directory(),
            self.compiled_extension()
        );
        let stderr_output = String::from_utf8(compile_output.stderr).unwrap();
        assert!(compile_output.status.success(), "{stderr_output}");
        let expected_compiled_output = compile_output.stdout;

        if fix {
            assert!(!running_on_ci(), "fix shouldn't be available on the CI.");

            println!("Fixing {path_str}.");
            fs::write(&existing_compiled_path, &expected_compiled_output).unwrap();
        }
        let expected_compiled_contents: Value =
            serde_json::from_str(&String::from_utf8(expected_compiled_output).unwrap()).unwrap();
        let existing_compiled_contents: Value =
            serde_json::from_str(&fs::read_to_string(&existing_compiled_path).unwrap()).unwrap();
        assert_eq!(
            existing_compiled_contents, expected_compiled_contents,
            "{path_str} does not compile to {existing_compiled_path}.\n Run `{FIX_COMMAND}` to \
             fix the expected test according to locally installed `starknet-compile-deprecated`."
        );
    }

    fn contracts_directory(&self) -> &String;

    // Expected extension for the compiled file.
    fn compiled_extension(&self) -> &str;
}
struct Cairo0FeatureContracts {
    contracts_dir: String,
    requirements_file: &'static str,
}

impl FeatureContracts for Cairo0FeatureContracts {
    fn check_deps(&self) {
        let cairo_lang_version_output = Command::new("sh")
            .arg("-c")
            .arg("pip freeze | grep cairo-lang")
            .output()
            .unwrap()
            .stdout;
        let cairo_lang_version = String::from_utf8(cairo_lang_version_output).unwrap();

        let requirements_contents = fs::read_to_string(self.requirements_file).unwrap();
        let expected_cairo_lang_version = requirements_contents
        .lines()
        .nth(1) // Skip docstring.
        .expect("Expecting requirements file to contain a docstring in the first line, and then the required cairo-lang version in the second line.");

        assert_eq!(
            cairo_lang_version.trim(),
            expected_cairo_lang_version.trim(),
            "cairo-lang not found. Please run:\n\
            pip3.9 install -r {}/{}\n\
            then rerun the test.",
            env::var("CARGO_MANIFEST_DIR").unwrap(),
            self.requirements_file
        );
    }

    fn compile(&self, path_str: &str, file_name: &str) -> Output {
        let mut command = Command::new("starknet-compile-deprecated");
        command.args([&path_str, "--no_debug_info"]);
        if file_name.starts_with("account") {
            command.arg("--account_contract");
        }
        if file_name.starts_with("security") {
            command.arg("--disable_hint_validation");
        }
        command.output().unwrap()
    }

    fn contracts_directory(&self) -> &String {
        &self.contracts_dir
    }

    // TODO: remove the compiled, doesn't serve a purpose while already inside a `compiled` dir.
    fn compiled_extension(&self) -> &str {
        "_compiled.json"
    }
}

struct Cairo1FeatureContracts {
    contracts_dir: String,
    cairo1_local_repo: &'static str,
    cairo1_version: String,
}

impl Cairo1FeatureContracts {
    // Expected location for the Cairo repo.
    fn cairo_repo_path(&self) -> PathBuf {
        // Location of blockifier's Cargo.toml.
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

        // Returns <blockifier_crate_root>/<RELATIVE_PATH_TO_CAIRO_REPO>.
        Path::new(&manifest_dir).join(self.cairo1_local_repo)
    }
}

impl FeatureContracts for Cairo1FeatureContracts {
    fn check_deps(&self) {
        let mut cairo_repo_path = self.cairo_repo_path();

        // On the CI, set the cairo repo location to <blockifier_crate_root>/../../../cairo, which
        // matches the one in compiled_cairo.yml.
        // Then checkout the tag as required by the test.
        if running_on_ci() {
            cairo_repo_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
            for _ in 0..3 {
                cairo_repo_path = cairo_repo_path.parent().unwrap().to_path_buf();
            }
            cairo_repo_path = cairo_repo_path.join("cairo");

            println!("CI action: cairo repo path in the CI set to {0}.", cairo_repo_path.to_string_lossy());

            println!("Checking out tag {}", self.cairo1_version);
            dbg!(Command::new("git")
                .args(["-C", &cairo_repo_path.to_str().unwrap(), "checkout", &self.cairo1_version])
                .output()
                .unwrap());
        }

        // Check if the path is a directory
        assert!(
            cairo_repo_path.is_dir(), 
            "Cannot verify Cairo1 contracts, Cairo repo not found at {0}.\n\
            Please run:\n\
            git clone https://github.com/starkware-libs/cairo {0} && git -C {0} checkout {1}\n\
            Then rerun the test.",
            cairo_repo_path.to_string_lossy(),
            self.cairo1_version
        );

        // Check if the directory is a git repository and if it's checked out to the specified tag.
        let status = Command::new("git")
            .args([
                "-C",
                &cairo_repo_path.to_str().unwrap(),
                "rev-parse",
                "--verify",
                &self.cairo1_version
            ])
            .stdout(std::process::Stdio::null()) // Redirect rev-parse spam to /dev/null
            .status()
            .unwrap();

        assert!(
            status.success(),
            "Cairo repo exists but isn't checked out in tag {0}.\n\
            Please run:\n\
            git -C {0} checkout {1}",
            cairo_repo_path.to_string_lossy(),
            self.cairo1_version
        );
    }

    fn contracts_directory(&self) -> &String {
        &self.contracts_dir
    }

    fn compile(&self, path_str: &str, _file_name: &str) -> Output {
        let mut cargo_command = Command::new("cargo");
        let sierra_output = cargo_command.args([
            "run",
            &format!("--manifest-path={}/Cargo.toml", self.cairo1_local_repo),
            "--bin",
            "starknet-compile",
            "--",
            "--single-file",
            &path_str,
        ]);
        let mut temp_file = NamedTempFile::new().unwrap();

        temp_file.write_all(&sierra_output.output().unwrap().stdout).unwrap();
        let temp_path_str = temp_file.into_temp_path();

        let mut cargo_command = Command::new("cargo");
        let casm_output = cargo_command.args([
            "run",
            &format!("--manifest-path={}/Cargo.toml", self.cairo1_local_repo),
            "--bin",
            "starknet-sierra-compile",
            temp_path_str.to_str().unwrap(),
        ]);

        casm_output.output().unwrap()
    }

    fn compiled_extension(&self) -> &str {
        ".casm.json"
    }
}

fn running_on_ci() -> bool {
    std::env::var("CI").is_ok()
}

#[test]
#[ignore]
fn verify_feature_contracts() {
    let fix_features = std::env::var("FIX_FEATURE_TEST").is_ok();

    // Cairo0FeatureContracts {
    //     contracts_dir: "feature_contracts/cairo0".to_string(),
    //     requirements_file: "tests/requirements.txt",
    // }
    // .verify(fix_features);

    Cairo1FeatureContracts {
        contracts_dir: "feature_contracts/cairo1".to_string(),
        cairo1_local_repo: "../../../cairo",
        cairo1_version: fs::read_to_string("tests/cairo1_version_for_fixtures.txt").unwrap().trim().to_string()
    }
    .verify(fix_features);
}
