#!/bin/env bash

set -e

function install_pypy() {
  pushd /opt
  $USE_SUDO bash -c '
  curl -Lo pypy3.9-v7.3.11-linux64.tar.bz2 https://downloads.python.org/pypy/pypy3.9-v7.3.11-linux64.tar.bz2
  tar -xf pypy3.9-v7.3.11-linux64.tar.bz2
  rm pypy3.9-v7.3.11-linux64.tar.bz2
  chmod +x pypy3.9-v7.3.11-linux64/bin/pypy3

  if [ -L /usr/local/bin/pypy3.9 ]; then
      unlink /usr/local/bin/pypy3.9
  fi

  ln -s /opt/pypy3.9-v7.3.11-linux64/bin/pypy3 /usr/local/bin/pypy3.9

  if [ -L /opt/pypy3.9 ]; then
      unlink /opt/pypy3.9
  fi

  ln -s /opt/pypy3.9-v7.3.11-linux64 /opt/pypy3.9
  pypy3.9 -m ensurepip
  pypy3.9 -m pip install wheel
  '
  popd
}

function install_rust () {
    curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path
}

install_pypy &
install_rust &
wait
