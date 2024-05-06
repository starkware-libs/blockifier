use std::process::Command;

/// Compiles a Cairo0 program using the deprecated compiler.
pub fn cairo0_compile(path: String, extra_arg: Option<String>, debug_info: bool) -> Vec<u8> {
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
pub fn cairo1_compile(_path: String) -> Vec<u8> {
    todo!();
}
