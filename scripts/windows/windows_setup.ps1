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

$rsa_config = @"
{
  "cert_configs": {
    "windows_store": {
      "issuer": "RSATestObject",
      "provider": "local_machine",
      "store": "MY"
    }
  },
  "libs": {
    "ecp": ".\\bin\\ecp",
    "ecp_client": ".\\bin\\libecp.dylib",
    "tls_offload": ".\\bin\\libtls_offload.dylib"
  }
}
"@

Out-File -FilePath rsa_certificate_config.json -InputObject $rsa_config

Get-ChildItem Cert:LocalMachine\My\ -Recurse
