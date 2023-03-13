filegroup(
    name = "native_blockifier_py",
    srcs = glob(["**"]),
    visibility =  ["//visibility:public"],
)

genrule(
    name = "copy_libnative_blockifier_so",
    srcs = ["//:libnative_blockifier.so"],
    outs = ["libnative_blockifier.so"],
    cmd = "cp $< $@" # Copy SRC to DST.
)

py_library(
    name = "native_blockifier_lib",
    srcs = [
        "__init__.py",
    ],
    visibility = ["//visibility:public"],
    data = [":libnative_blockifier.so"],
)
