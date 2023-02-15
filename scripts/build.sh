#!/bin/bash
set -ex

root_dir="$(cd `dirname $0` && pwd -P)/../"

docker run --rm -v $root_dir:/io quay.io/pypa/manylinux2014_x86_64 bash /io/scripts/build_wheels.sh
