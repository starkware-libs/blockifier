#!/bin/bash
set -ex

root_dir="$(cd `dirname $0` && pwd -P)/../"

docker run -e GIT_REF=$2 --rm -v $root_dir:/io quay.io/pypa/manylinux2014_x86_64 bash /io/scripts/build_wheels.sh

for i in dist/*many*.whl
    do s3pypi -b pypi.starkex.co --unsafe-s3-website --put-root-index $i
done
