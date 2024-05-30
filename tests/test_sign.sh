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

SOFTHSM2_MODULE="/usr/lib/softhsm/libsofthsm2.so"
SLOT=$(cat ec_certificate_config.json | jq .cert_configs.pkcs11.slot -r)
export ENABLE_ENTERPRISE_CERTIFICATE_LOGS=1

ec_test() {
    export GOOGLE_API_CERTIFICATE_CONFIG="$PWD/ec_certificate_config.json"

    WORKDIR=$(mktemp -d)
    pushd $WORKDIR

    TEST_OBJECT="EC Test Object"

    echo "hello world" >> input.txt

    # Create Digest
    $OPENSSL_CLI dgst -sha256 -binary -out sha256.bin input.txt

    # Sign with ECP
    $OPENSSL_CLI pkeyutl -sign -inkey ecp:1 -in sha256.bin -out sha256-ecsig.bin -provider $PROVIDER_PATH

     # Extract public key
    $OPENSSL_CLI x509 -noout -pubkey -in $EC_CLIENT_CERT -out pubkey.pem

    # Verify ECP signature
    $OPENSSL_CLI pkeyutl -verify -inkey pubkey.pem -sigfile sha256-ecsig.bin -pubin -in sha256.bin
    popd
}

rsa_test() {
    export GOOGLE_API_CERTIFICATE_CONFIG="$PWD/rsa_certificate_config.json"

    WORKDIR=$(mktemp -d)
    pushd $WORKDIR

    TEST_OBJECT="RSA Test Object"

    echo "hello world" >> input.txt

    # Create Digest
    $OPENSSL_CLI dgst -sha256 -binary -out sha256.bin input.txt

    # Sign with ECP
    $OPENSSL_CLI pkeyutl -sign -inkey ecp:1 -in sha256.bin -out sha256-ecsig.bin -provider $PROVIDER_PATH

     # Extract public key
    $OPENSSL_CLI x509 -noout -pubkey -in $RSA_CLIENT_CERT -out pubkey.pem

    # Verify ECP signature
    $OPENSSL_CLI pkeyutl -verify -inkey pubkey.pem -sigfile sha256-ecsig.bin -pubin -in sha256.bin  -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:32
    popd
}

ec_test
rsa_test
