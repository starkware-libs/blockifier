#!/bin/bash
set -e

pushd /io/crates/native_blockifier/

# Install crate dependencies.
yum -y install centos-release-scl
yum -y install openssl-devel llvm-toolset-7.0

# Install Rust.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

export PATH="$HOME/.cargo/bin:$PATH"

# Required for libclang > 3.9, by default there is only clang 3.4 in this image.
source /opt/rh/llvm-toolset-7.0/enable

cpython_bins=$(echo /opt/python/cp{37,38,39,310}*/bin)
pypy_bins=$(echo /opt/python/pp{37,38,39}*/bin)

# Compile wheels.
for py_bin in ${cpython_bins} ${pypy_bins}; do
    rm -rf build/
    "${py_bin}/pip" install -U setuptools setuptools-rust wheel
    "${py_bin}/pip" wheel ./ -w ./dist/ --no-deps
done

# Bundle external shared libraries into the wheels.
for whl in dist/*{cp37,cp38,cp39,cp310,pp37,pp38,pp39}*.whl; do
    auditwheel repair "$whl" -w ./dist/
done

# Install packages and test.
for py_bin in ${cpython_bins} ${pypy_bins}; do
    "${py_bin}/pip" install native_blockifier -f /io/dist/
    echo "Testing with $("${py_bin}/python" --version) ..."
    "${py_bin}/python" -c "import native_blockifier; print('native_blockifier import success')"
done

popd
