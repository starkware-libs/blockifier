use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{env, fs};

use cached::proc_macro::cached;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

const CAIRO0_PIP_REQUIREMENTS_FILE: &str = "tests/requirements.txt";
const LOCAL_CAIRO1_REPO_RELATIVE_PATH: &str = "../../../cairo";

/// Objects for simple deserialization of Cargo.toml to fetch the Cairo1 compiler version.
/// The compiler itself isn't actually a dependency, so we compile by using the version of the
/// cairo-lang-casm crate.
/// The choice of cairo-lang-casm is arbitrary, as all compiler crate dependencies should have the
/// same version.
/// Deserializes:
/// """
/// ...
/// [workspace.dependencies]
/// ...
/// cairo-lang-casm = VERSION
/// ...
/// """
/// where `VERSION` can be a simple "x.y.z" version string or an object with a "version" field.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum DependencyValue {
    String(String),
    Object { version: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct CairoLangCasmDependency {
    #[serde(rename = "cairo-lang-casm")]
    cairo_lang_casm: DependencyValue,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkspaceFields {
    dependencies: CairoLangCasmDependency,
}

#[derive(Debug, Serialize, Deserialize)]
struct CargoToml {
    workspace: WorkspaceFields,
}

#[cached]
/// Returns the version of the Cairo1 compiler* defined in the root Cargo.toml.
pub fn cairo1_compiler_version() -> String {
    let cargo_toml: CargoToml = toml::from_str(include_str!("../../../../Cargo.toml")).unwrap();
    match cargo_toml.workspace.dependencies.cairo_lang_casm {
        DependencyValue::String(version) | DependencyValue::Object { version } => version.clone(),
    }
}

/// Returns the path to the local Cairo1 compiler repository.
fn local_cairo1_compiler_repo_path() -> PathBuf {
    // Location of blockifier's Cargo.toml.
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Returns <blockifier_crate_root>/<RELATIVE_PATH_TO_CAIRO_REPO>.
    Path::new(&manifest_dir).join(LOCAL_CAIRO1_REPO_RELATIVE_PATH)
}

/// Run a command, assert exit code is zero (otherwise panic with stderr output).
fn run_and_verify_output(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    if !output.status.success() {
        let stderr_output = String::from_utf8(output.stderr).unwrap();
        panic!("{stderr_output}");
    }
    output
}

/// Compiles a Cairo0 program using the deprecated compiler.
pub fn cairo0_compile(path: String, extra_arg: Option<String>, debug_info: bool) -> Vec<u8> {
    verify_cairo0_compiler_deps();
    let mut command = Command::new("starknet-compile-deprecated");
    if let Some(extra_arg) = extra_arg {
        command.arg(extra_arg);
    }
    if !debug_info {
        command.args([&path, "--no_debug_info"]);
    }
    let compile_output = command.output().unwrap();
    let stderr_output = String::from_utf8(compile_output.stderr).unwrap();
    assert!(compile_output.status.success(), "{stderr_output}");
    compile_output.stdout
}

/// Compiles a Cairo1 program using the compiler version set in the Cargo.toml.
pub fn cairo1_compile(path: String, git_tag_override: Option<String>) -> Vec<u8> {
    verify_cairo1_compiler_deps(git_tag_override);
    let cairo1_compiler_path = local_cairo1_compiler_repo_path();
    let mut cargo_command = Command::new("cargo");
    let sierra_output = run_and_verify_output(cargo_command.args([
        "run",
        &format!("--manifest-path={}/Cargo.toml", cairo1_compiler_path.to_string_lossy()),
        "--bin",
        "starknet-compile",
        "--",
        "--single-file",
        &path,
    ]));
    let mut temp_file = NamedTempFile::new().unwrap();

    temp_file.write_all(&sierra_output.stdout).unwrap();
    let temp_path_str = temp_file.into_temp_path();

    let mut cargo_command = Command::new("cargo");
    let casm_output = run_and_verify_output(cargo_command.args([
        "run",
        &format!("--manifest-path={}/Cargo.toml", cairo1_compiler_path.to_string_lossy()),
        "--bin",
        "starknet-sierra-compile",
        temp_path_str.to_str().unwrap(),
    ]));

    casm_output.stdout
}

/// Verifies that the required dependencies are available before compiling.
fn verify_cairo0_compiler_deps() {
    // Python compiler. Verify correct version.
    let cairo_lang_version_output =
        Command::new("sh").arg("-c").arg("pip freeze | grep cairo-lang").output().unwrap().stdout;
    let cairo_lang_version = String::from_utf8(cairo_lang_version_output).unwrap();

    let requirements_contents = fs::read_to_string(CAIRO0_PIP_REQUIREMENTS_FILE).unwrap();
    let expected_cairo_lang_version = requirements_contents
        .lines()
        .nth(1) // Skip docstring.
        .expect(
            "Expecting requirements file to contain a docstring in the first line, and \
            then the required cairo-lang version in the second line."
        );

    assert_eq!(
        cairo_lang_version.trim(),
        expected_cairo_lang_version.trim(),
        "cairo-lang not found. Please run:\npip3.9 install -r {}/{}\nthen rerun the test.",
        env::var("CARGO_MANIFEST_DIR").unwrap(),
        CAIRO0_PIP_REQUIREMENTS_FILE
    );
}

fn verify_cairo1_compiler_deps(git_tag_override: Option<String>) {
    // TODO(Dori, 1/6/2024): Check repo exists.
    let tag = git_tag_override.unwrap_or(format!("v{}", cairo1_compiler_version()));
    // Checkout the required version in the compiler repo.
    run_and_verify_output(Command::new("git").args([
        "-C",
        // TODO(Dori, 1/6/2024): Handle CI case (repo path will be different).
        &local_cairo1_compiler_repo_path().to_str().unwrap(),
        "checkout",
        &tag,
    ]));
}
