#!/bin/env bash
set -e

docker_image_name=blockifier-ci
docker build . -t ${docker_image_name}

docker run \
    --rm \
    --net host \
    -e CARGO_HOME=${HOME}/.cargo \
    -e PYO3_PYTHON=/usr/local/bin/pypy3.9 \
    -u $UID \
    -v /tmp:/tmp \
    -v "${HOME}:${HOME}" \
    --workdir ${PWD} \
    ${docker_image_name} \
    cargo build --release -p native_blockifier --features=testing
