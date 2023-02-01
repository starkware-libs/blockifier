#!/bin/bash
set -e

# The starknet-api dependency requires the dependency `rust-openssl`, which needs openssl-devel
# to be installed locally.
yum -y install  centos-release-scl


yum -y install openssl-devel llvm-toolset-7.0


curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Exports
#export LD_LIBRARY_PATH=/opt/rh/llvm-toolset-7.0/root/usr/lib64/
export PATH="$HOME/.cargo/bin:$PATH"

scl enable llvm-toolset-7.0 "bash /io/run_in_chroot.sh"
