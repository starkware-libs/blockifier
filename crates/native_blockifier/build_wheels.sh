#!/bin/bash
set -e

# Install crate dependencies
yum -y install centos-release-scl
yum -y install openssl-devel llvm-toolset-7.0


# Install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

export PATH="$HOME/.cargo/bin:$PATH"

# Required for libclang > 3.9, by default there is only clang 3.4 in this image.
scl enable llvm-toolset-7.0 "bash /io/run_in_chroot.sh"
