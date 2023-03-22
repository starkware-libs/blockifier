load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")
load("@rules_python//python:defs.bzl", "py_library")

rust_library(
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

genrule(
    name = "native_blockifier.so",
    srcs = ["native_blockifier"],
    outs = ["native_blockifier.so"],
    cmd = "cp $< $@",
)

py_library(
    name = "native_blockifier_py",
    srcs = ["native_blockifier/__init__.py"],
    data = ["native_blockifier.so"],
    visibility = ["//visibility:public"],
)
