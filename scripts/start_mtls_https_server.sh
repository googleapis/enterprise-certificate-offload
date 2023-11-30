#!/bin/zsh

# Copyright 2023 Google LLC.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eux

source scripts/credential_names.sh

echo "hello world" > input.txt
echo "OK" > response.txt

$OPENSSL_CLI s_server -accept 8888 -Verify 1 -cert "$EC_SERVER_CERT" -key "$EC_SERVER_KEY" -CAfile "$EC_CLIENT_CERT" &>/tmp/mtls_server_logs.txt < response.txt -debug -state -WWW&

$OPENSSL_CLI s_server -accept 8889 -Verify 1 -cert "$RSA_SERVER_CERT" -key "$RSA_SERVER_KEY" -CAfile "$RSA_CLIENT_CERT" &>/tmp/mtls_server_logs.txt < response.txt -debug -state -WWW&
