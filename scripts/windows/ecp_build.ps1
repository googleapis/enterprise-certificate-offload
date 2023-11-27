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

if (Test-Path $env:ECP_BIN_DIR) {
    Remove-Item -Force -Recurse $env:ECP_BIN_DIR
}

New-Item -ItemType Directory -Path $env:ECP_BIN_DIR

git clone https://github.com/googleapis/enterprise-certificate-proxy.git --depth=1
Push-Location enterprise-certificate-proxy

.\build\scripts\windows\windows_amd64.ps1
Copy-Item .\build\bin\windows_amd64\* $env:ECP_BIN_DIR

Pop-Location
