"""Build rules for PyO3"""

load("@rules_rust//rust:rust.bzl", "rust_library")
load("@rules_python//python:defs.bzl", "py_library")

def pyo3_extension(
        name,
        deps = [],
        py_srcs = [],
        visibility = None,
        **kwargs):
    """
    Creates a PyO3 extension.
    Args:
        name: The name of the resulting `py_library`
        deps: The dependencies of the extension, not including PyO3.
        py_srcs: The contents of the `srcs` attribute for the resulting `py_library`.
            Useful for adding `__init__.py` files
        visibility: The visibility of the .so and the python library
        **kwargs: Forwarded along directly to `rust_library`
    """

    name_rs = name + "_rs"
    name_so = name + ".so"

    rust_library(
        name = name_rs,
        deps = ["@rules_pyo3//:pyo3"] + deps,
        crate_type = "cdylib",
        visibility = ["//visibility:private"],
        **kwargs
    )

    native.genrule(
        name = name_so,
        srcs = [":" + name_rs],
        outs = [name_so],
        visibility = visibility,
        cmd = "cp $< $@",
    )

    py_library(
        name = name,
        srcs = py_srcs,
        data = [name_so],
        visibility = visibility,
    )
