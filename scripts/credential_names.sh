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

export EC_SERVER_KEY="$PWD/ec_prime256v1_serverkey.pem"
export EC_SERVER_CERT="$PWD/ec_prime256v1_servercert.pem"

export EC_CLIENT_KEY="$PWD/ec_prime256v1_clientkey.pem"
export EC_CLIENT_CERT="$PWD/ec_prime256v1_clientcert.pem"

export RSA_SERVER_KEY="$PWD/rsa_2048_serverkey.pem"
export RSA_SERVER_CERT="$PWD/rsa_2048_servercert.pem"

export RSA_CLIENT_KEY="$PWD/rsa_2048_clientkey.pem"
export RSA_CLIENT_CERT="$PWD/rsa_2048_clientcert.pem"

export EC_ISSUER="EC Test Object"
export RSA_ISSUER="RSA Test Object"

export PROVIDER_PATH=$(ls $PWD/bin/libecp_provider*)
