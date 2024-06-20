load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_shared_library")
load("@rules_python//python:defs.bzl", "py_library")

exports_files(["Cargo.toml"])

rust_shared_library(
    name = "native_blockifier",
    srcs = glob([
        "src/**/*.rs",
    ]),
    crate_features = ["testing"],
    data = ["Cargo.toml"],
    rustc_env = {
        "CARGO_MANIFEST_DIR": ".",
    },
    visibility = ["//crates:__subpackages__"],
    deps = all_crate_deps() + ["//crates/blockifier"],
)

genrule(
    name = "native_blockifier.pypy39-pp73-x86_64-linux-gnu.so",
    srcs = ["native_blockifier"],
    outs = ["native_blockifier/native_blockifier.pypy39-pp73-x86_64-linux-gnu.so"],
    cmd = "cp $< $@",
)

py_library(
    name = "native_blockifier_py",
    srcs = ["native_blockifier/__init__.py"],
    data = [
        "Cargo.toml",
        "native_blockifier.pypy39-pp73-x86_64-linux-gnu.so",
    ],
    imports = ["."],  # Allow using "import native_blockifier" directly in any Python code.
    visibility = ["//visibility:public"],
)
