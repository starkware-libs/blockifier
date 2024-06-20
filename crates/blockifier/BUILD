load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

exports_files(["Cargo.toml"])

rust_library(
    name = "blockifier",
    srcs = glob(["src/**/*.rs"]),
    compile_data = ["Cargo.toml"],
    crate_features = [
        "testing",
        "concurrency",
    ],
    data = glob(
        ["resources/**/*"],
        ["Cargo.toml"],
    ),
    edition = "2021",
    proc_macro_deps = all_crate_deps(proc_macro = True),
    visibility = ["//crates:__subpackages__"],
    deps = all_crate_deps(),
)
