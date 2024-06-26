#!/bin/env bash

set -e

function install_rust () {
    curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path
}

source ./install_pypy.sh

install_pypy &
install_rust &
wait
