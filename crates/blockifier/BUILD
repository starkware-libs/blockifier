load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name = "blockifier",
    srcs = glob(["src/**/*.rs"]),
    visibility = ["//crates:__subpackages__"],
    deps = all_crate_deps(),
    proc_macro_deps = all_crate_deps(proc_macro = True),
    edition = "2021",
)
