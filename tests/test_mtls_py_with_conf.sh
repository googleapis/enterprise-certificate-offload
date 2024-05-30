#!/bin/zsh

set -eux

# Make sure this isn't "GOOGLE_API_CERTIFICATE_CONFIG" to clash with the ENV variable way to
# specify config.
source scripts/credential_names.sh
export ENABLE_ENTERPRISE_CERTIFICATE_LOGS=1

python3 -m venv env && source env/bin/activate
python3 -m pip install requests

export OPENSSL_CONF=$PWD/ecp_openssl.conf

ec_test() {
    export GOOGLE_API_CERTIFICATE_CONFIG_PATH="$PWD/ec_certificate_config.json"
    cat <<EOF > $OPENSSL_CONF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
ecp_provider = ecp_sect
default = default_sect

[default_sect]
activate = 1

[base_sect]
activate = 1

[ecp_sect]
activate = 1
module = $PROVIDER_PATH
ecp_config_path = $GOOGLE_API_CERTIFICATE_CONFIG_PATH
EOF
    python3 tests/test_mtls.py
}

rsa_test() {
    export GOOGLE_API_CERTIFICATE_CONFIG_PATH="$PWD/rsa_certificate_config.json"
    cat <<EOF > $OPENSSL_CONF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
ecp_provider = ecp_sect
default = default_sect

[default_sect]
activate = 1

[base_sect]
activate = 1

[ecp_sect]
activate = 1
module = $PROVIDER_PATH
ecp_config_path = $GOOGLE_API_CERTIFICATE_CONFIG_PATH
EOF
    python3 tests/test_mtls.py
}

ec_test
rsa_test

echo "PASSED"
