#!/bin/bash
# Copyright 2022 Google LLC.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -eu

function check_dependencies() {
  if ! command -v python &> /dev/null
  then
      echo "Please install Python before running this script."
      exit
  fi
  if ! command -v go &> /dev/null
  then
      echo "Please install go before running this script."
      exit
  fi
}

function start_local_mtls_server() {
  go run -v ./tests/testing_utils/server/server.go &> local_mtls_server_logs.txt
}

function run_integration_test() {
  python -m pip install -r tests/testing_utils/requirements.txt > /dev/null
  python -m pytest tests/integration_test.py
}

check_dependencies
start_local_mtls_server&
run_integration_test
