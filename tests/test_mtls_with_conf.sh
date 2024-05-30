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

# Make sure this isn't "GOOGLE_API_CERTIFICATE_CONFIG" to clash with the ENV variable way to
# specify config.
export OPENSSL_CONF=$PWD/ecp_openssl.conf
export ENABLE_ENTERPRISE_CERTIFICATE_LOGS=1

ec_test() {
    GOOGLE_API_CERTIFICATE_CONFIG_PATH="$PWD/ec_certificate_config.json"
    cat <<EOF > $OPENSSL_CONF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
ecp_provider = ecp_sect
default = default_sect
base = base_sect

[default_sect]
activate = 1

[base_sect]
activate = 1

[ecp_sect]
activate = 1
module = $PROVIDER_PATH
ecp_config_path = $GOOGLE_API_CERTIFICATE_CONFIG_PATH
EOF

    echo "Q" | $OPENSSL_CLI s_client -connect localhost:8888 -cert "$EC_CLIENT_CERT" -key ecp:1 -CAfile "$EC_SERVER_CERT"

    echo "EC Result: $?"
}

rsa_test() {
    GOOGLE_API_CERTIFICATE_CONFIG_PATH="$PWD/rsa_certificate_config.json"
    cat <<EOF > $OPENSSL_CONF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
ecp_provider = ecp_sect
default = default_sect
base = base_sect

[default_sect]
activate = 1

[base_sect]
activate = 1

[ecp_sect]
activate = 1
module = $PROVIDER_PATH
ecp_config_path = $GOOGLE_API_CERTIFICATE_CONFIG_PATH
EOF

    echo "Q" | $OPENSSL_CLI s_client -connect localhost:8889 -cert "$RSA_CLIENT_CERT" -key ecp:1 -CAfile "$RSA_SERVER_CERT"

    echo "RSA Result: $?"
}

ec_test
rsa_test

echo "PASSED"
