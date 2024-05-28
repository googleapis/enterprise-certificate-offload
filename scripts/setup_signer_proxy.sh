#!/bin/bash
# Copyright 2022 Google LLC.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -eu

function check_dependencies() {
  if ! command -v git &> /dev/null
  then
      echo "Please install git before running this script."
      exit
  fi
  if ! command -v go &> /dev/null
  then
      echo "Please install go before running this script."
      exit
  fi
}

function set_up_env() {
  ENTERPRISE_CERTIFICATE_PROXY_REPO="https://github.com/googleapis/enterprise-certificate-proxy.git"

  if [[ "$(uname)" == 'Linux' ]]; then
     BUILD_SCRIPT="build/scripts/linux_amd64.sh"
     SIGNER_BINARY="build/bin/linux_amd64/ecp"
     SIGNER_SHARED_LIB="build/bin/linux_amd64/libecp.so"
     TEST_BINARY_FOLDER="$PWD/tests/testing_utils/signer_binaries/linux64"
  elif [[ "$(uname)" == 'Darwin' ]]; then
     BUILD_SCRIPT="build/scripts/darwin_amd64.sh"
     SIGNER_BINARY="build/bin/darwin_amd64/ecp"
     SIGNER_SHARED_LIB="build/bin/darwin_amd64/libecp.dylib"
     TEST_BINARY_FOLDER="$PWD/tests/testing_utils/signer_binaries/mac64"
  else
    echo "This script only supports Linux and MacOS."
    exit 1
  fi
}

function install_proxy_binaries() {
  BUILD_DIR=$(mktemp -d proxy_signer_buildXXX)
  pushd "$BUILD_DIR"
  git clone $ENTERPRISE_CERTIFICATE_PROXY_REPO --depth 1
  pushd enterprise-certificate-proxy

  sh "$BUILD_SCRIPT"

  mkdir -p "$TEST_BINARY_FOLDER"

  mv "$SIGNER_BINARY" "$TEST_BINARY_FOLDER"
  mv "$SIGNER_SHARED_LIB" "$TEST_BINARY_FOLDER"

  popd
  popd
  rm -rf "$BUILD_DIR"
}

check_dependencies
set_up_env
install_proxy_binaries
