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

export ENABLE_ENTERPRISE_CERTIFICATE_LOGS=1

ec_test() {
    export GOOGLE_API_CERTIFICATE_CONFIG="$PWD/ec_certificate_config.json"
    echo "Q" | $OPENSSL_CLI s_client -connect localhost:8888 -cert "$EC_CLIENT_CERT" -key ecp:1 -CAfile "$EC_SERVER_CERT" -provider base -provider default -provider legacy -provider $PROVIDER_PATH
    echo "EC Result: $?"
}

rsa_test() {
    export GOOGLE_API_CERTIFICATE_CONFIG="$PWD/rsa_certificate_config.json"
    echo "Q" | $OPENSSL_CLI s_client -connect localhost:8889 -cert "$RSA_CLIENT_CERT" -key ecp:1 -CAfile "$RSA_SERVER_CERT" -provider base -provider default -provider legacy -provider $PROVIDER_PATH
    echo "RSA Result: $?"
}

ec_test
rsa_test

echo "PASSED"
