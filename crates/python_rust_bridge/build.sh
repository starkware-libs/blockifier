#!/bin/bash
set -ex

docker run --rm -v `pwd`:/io quay.io/pypa/manylinux2014_x86_64 bash /io/build_wheels.sh

