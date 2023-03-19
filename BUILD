package(default_visibility = ["//visibility:public"])

exports_files(glob(["**"]))

genrule(
    name = "run_cargo",
    srcs = glob(
        [
            "docs/**",
            "scripts/**",
            "Cargo.toml",
            "Cargo.lock",
        ],
    ) + [
        "//crates",
        "//crates/native_blockifier",
    ],
    outs = ["libnative_blockifier.so"],
    cmd = """
    pushd $$(dirname $(location Cargo.toml))
    ~/.cargo/bin/cargo build
    popd
    cp $$(dirname $(location Cargo.toml))/target/debug/libnative_blockifier.so $@
  """,
    local = True,
)
