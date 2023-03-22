load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_static_library")

rust_static_library(
    name = "native_blockifier",
    srcs = [
        "src/errors.rs",
        "src/lib.rs",
        "src/py_state_diff.rs",
        "src/py_test_utils.rs",
        "src/py_transaction_execution_info.rs",
        "src/py_transaction.rs",
        "src/py_utils.rs",
        "src/storage.rs",
    ],
    visibility = ["//crates:__subpackages__"],
    deps = all_crate_deps() + ["//crates/blockifier"],
)
