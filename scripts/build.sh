#!/bin/bash
set -ex

function deploy_to_pypi_proxy() {
    for whl in crates/native_blockifier/dist/*many*.whl
        do s3pypi -b pypi.starkex.co --unsafe-s3-website --put-root-index $whl
    done
}

root_dir="$(cd `dirname $0` && pwd -P)/../"

docker run -e GIT_REF=$2 --rm -v $root_dir:/io quay.io/pypa/manylinux2014_x86_64 bash /io/scripts/build_wheels.sh

deploy_to_pypi_proxy()
