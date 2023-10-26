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

TOKEN_NAME="Test Token"
EC_OBJECT_LABEL="EC Test Object"
RSA_OBJECT_LABEL="RSA Test Object"
PIN="0000"

BUILD_DIR=$(mktemp -d)

setup_pkcs11_module() {
  # Make softhsm2 discoverable by PKCS #11 tools.
  sudo mkdir -p /etc/pkcs11/modules && echo "module: /usr/lib/softhsm/libsofthsm2.so" | sudo tee -a /etc/pkcs11/modules/softhsm.module

  if [[ -d $HOME/.config/softhsm2/tokens ]]; then
      rm -rf $HOME/.config/softhsm2/tokens
  fi

  # Create folder for storing PKCS #11 objects
  mkdir -p $HOME/.config/softhsm2/tokens

  cat <<EOF > $HOME/.config/softhsm2/softhsm2.conf
directories.tokendir = $HOME/.config/softhsm2/tokens/
objectstore.backend = file
log.level = INFO
slots.removable = true
EOF

  pkcs11-tool --init-token --label "$TOKEN_NAME" --module $SOFTHSM2_MODULE --slot 0 --so-pin $PIN
  SLOT=$(pkcs11-tool --list-slots --module $SOFTHSM2_MODULE | grep  -Eo "0x[A-Fa-f0-9]+" | head -n 1)
  pkcs11-tool --module $SOFTHSM2_MODULE --token-label "$TOKEN_NAME" --login --init-pin --pin $PIN --so-pin $PIN

  pushd $BUILD_DIR

  $OPENSSL_CLI x509 -pubkey -noout -in "$EC_CLIENT_CERT" > public_key.pem

  $OPENSSL_CLI x509 -in "$EC_CLIENT_CERT" -out cert.der -outform der
  $OPENSSL_CLI ec -in "$EC_CLIENT_KEY" -outform DER -out private_key.der
  $OPENSSL_CLI ec -inform pem -in public_key.pem -outform der -out public_key.der -pubin

  pkcs11-tool --module $SOFTHSM2_MODULE --slot $SLOT --write-object cert.der --type cert --label "$EC_OBJECT_LABEL" --login --pin $PIN
  pkcs11-tool --module $SOFTHSM2_MODULE --slot $SLOT --write-object private_key.der --type privkey --label "$EC_OBJECT_LABEL" --login --pin $PIN
  pkcs11-tool --module $SOFTHSM2_MODULE --slot $SLOT --write-object public_key.der --type pubkey --label "$EC_OBJECT_LABEL" --login --pin $PIN

  $OPENSSL_CLI x509 -pubkey -noout -in "$RSA_CLIENT_CERT" > public_key.pem

  $OPENSSL_CLI x509 -in "$RSA_CLIENT_CERT" -out cert.der -outform der
  $OPENSSL_CLI rsa -in "$RSA_CLIENT_KEY" -outform DER -out private_key.der
  $OPENSSL_CLI rsa -inform pem -in public_key.pem -outform der -out public_key.der -pubin

  pkcs11-tool --module $SOFTHSM2_MODULE --slot $SLOT --write-object cert.der --type cert --label "$RSA_OBJECT_LABEL" --login --pin $PIN
  pkcs11-tool --module $SOFTHSM2_MODULE --slot $SLOT --write-object private_key.der --type privkey --label "$RSA_OBJECT_LABEL" --login --pin $PIN
  pkcs11-tool --module $SOFTHSM2_MODULE --slot $SLOT --write-object public_key.der --type pubkey --label "$RSA_OBJECT_LABEL" --login --pin $PIN

  popd
}

create_ec_config() {
  cat << EOF > ec_certificate_config.json
{
  "cert_configs": {
    "pkcs11": {
      "module": "$SOFTHSM2_MODULE",
      "slot": "$SLOT",
      "label": "$EC_OBJECT_LABEL",
      "user_pin": "$PIN"
    }
  },
  "libs": {
    "ecp": "$ECP_BIN_DIR/ecp",
    "ecp_client": "$ECP_BIN_DIR/libecp.so",
    "tls_offload": "$ECP_BIN_DIR/libtls_offload.so"
  }
}
EOF
}

create_rsa_config() {
  cat << EOF > rsa_certificate_config.json
{
  "cert_configs": {
    "pkcs11": {
      "module": "$SOFTHSM2_MODULE",
      "slot": "$SLOT",
      "label": "$RSA_OBJECT_LABEL",
      "user_pin": "$PIN"
    }
  },
  "libs": {
    "ecp": "$ECP_BIN_DIR/ecp",
    "ecp_client": "$ECP_BIN_DIR/libecp.so",
    "tls_offload": "$ECP_BIN_DIR/libtls_offload.so"
  }
}
EOF
}

setup_pkcs11_module
create_ec_config
create_rsa_config
