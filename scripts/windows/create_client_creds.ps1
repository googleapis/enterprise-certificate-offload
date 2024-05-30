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

openssl req -x509 -newkey rsa:2048 -keyout "$env:RSA_CLIENT_KEY" -out "$env:RSA_CLIENT_CERT" -sha256 -days 365 -nodes -subj "/C=US/ST=WA/L=Sea/O=My Inc/OU=DevOps/CN=RSATestObject/"

openssl pkcs12 -inkey $env:RSA_CLIENT_KEY -in $env:RSA_CLIENT_CERT -export -out cred.p12 -passin pass:1234 -passout pass:1234

$pass = ConvertTo-SecureString -String "1234" -AsPlainText -Force
Import-PfxCertificate -FilePath "cred.p12" -CertStoreLocation "Cert:\LocalMachine\My" -Password $pass
