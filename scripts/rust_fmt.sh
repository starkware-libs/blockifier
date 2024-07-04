#!/bin/bash

# Install toolchain if missing (local run).
TOOLCHAIN="nightly-2024-04-29"
rustup toolchain list | grep -q ${TOOLCHAIN} || rustup toolchain install ${TOOLCHAIN}

cargo +${TOOLCHAIN} fmt --all -- "$@"
