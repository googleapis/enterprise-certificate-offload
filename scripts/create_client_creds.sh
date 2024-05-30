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

$OPENSSL_CLI req -x509 -newkey ec:<($OPENSSL_CLI ecparam -name prime256v1) -keyout "$EC_CLIENT_KEY" -out "$EC_CLIENT_CERT" -sha256 -days 365 -nodes -subj "/C=US/ST=WA/L=Sea/O=My Inc/OU=DevOps/CN=${EC_ISSUER}/emailAddress=dev@www.example.com"


$OPENSSL_CLI req -x509 -newkey rsa:2048 -keyout "$RSA_CLIENT_KEY" -out "$RSA_CLIENT_CERT" -sha256 -days 365 -nodes -subj "/C=US/ST=WA/L=Sea/O=My Inc/OU=DevOps/CN=${RSA_ISSUER}/emailAddress=dev@www.example.com"
