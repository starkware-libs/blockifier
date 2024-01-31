load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name="blockifier",
    srcs=glob(["src/**/*.rs"]),
    data=glob(["resources/**/*"]),
    visibility=["//crates:__subpackages__"],
    deps=all_crate_deps(),
    proc_macro_deps=all_crate_deps(proc_macro=True),
    edition="2021",
    crate_features=["testing"],
)
