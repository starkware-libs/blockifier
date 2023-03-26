load("@crates//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_shared_library")
load("@rules_python//python:defs.bzl", "py_library")

rust_shared_library(
    name = "native_blockifier",
    srcs = glob(["src/**/*.rs"]),
    visibility = ["//crates:__subpackages__"],
    deps = all_crate_deps() + ["//crates/blockifier"],
)

genrule(
    name = "native_blockifier.so",
    srcs = ["native_blockifier"],
    outs = ["native_blockifier/native_blockifier.so"],
    cmd = "cp $< $@",
)

py_library(
    name = "native_blockifier_py",
    srcs = ["native_blockifier/__init__.py"],
    data = ["native_blockifier.so"],
    imports = ["."], # Allow using "import native_blockifier" directly in any python code.
    visibility = ["//visibility:public"],
)
