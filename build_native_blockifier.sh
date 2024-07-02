#!/bin/env bash
set -e

./docker_cargo.sh build --release -p native_blockifier --features "testing"
