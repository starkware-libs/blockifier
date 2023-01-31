#!/bin/bash
set -e

# The starknet-api dependency requires the dependency `rust-openssl`, which needs openssl-devel
# to be installed locally.
yum -y install openssl-devel

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"


cpython_bins=$(echo /opt/python/cp{37,38,39,310}*/bin)
pypy_bins=$(echo /opt/python/pp{37,38,39}*/bin)

# Compile wheels
for py_bin in ${cpython_bins} ${pypy_bins}; do
    rm -rf /io/build/
    "${py_bin}/pip" install -U setuptools setuptools-rust wheel
    "${py_bin}/pip" wheel /io/ -w /io/dist/ --no-deps
done

# Bundle external shared libraries into the wheels
for whl in /io/dist/*{cp37,cp38,cp39,cp310,pp37,pp38,pp39}*.whl; do
    auditwheel repair "$whl" -w /io/dist/
done

# Install packages and test
for py_bin in ${cpython_bins} ${pypy_bins}; do
    "${py_bin}/pip" install native_blockifier -f /io/dist/
    echo "Testing with $("${py_bin}/python" --version) ..."
    "${py_bin}/python" -c "import native_blockifier; native_blockifier.hello_world()"
done
