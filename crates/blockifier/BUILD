load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name = "blockifier",
    srcs = glob(["src/**/*.rs"]),
    crate_features = [
        "concurrency",
        "jemalloc",
        "testing",
    ],
    data = glob(["resources/**/*"]),
    edition = "2021",
    proc_macro_deps = all_crate_deps(proc_macro = True),
    visibility = ["//crates:__subpackages__"],
    deps = all_crate_deps(),
)
