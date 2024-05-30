Set-PSDebug -Trace 2

$openssl_config = @"
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
module = $env:PROVIDER_PATH
"@

Out-File -FilePath ecp_openssl.conf -InputObject $rsa_config

python3 -m venv env
env\Scripts\Activate.ps1
python3 -m pip install requests

$env:OPENSSL_CONF = (Get-Item ecp_openssl.conf | Resolve-Path).ProviderPath
$env:GOOGLE_API_CERTIFICATE_CONFIG = (Get-Item rsa_certificate_config.json | Resolve-Path).ProviderPath
$env:GOOGLE_API_CERTIFICATE_CONFIG_PATH = (Get-Item rsa_certificate_config.json | Resolve-Path).ProviderPath
$env:ENABLE_ENTERPRISE_CERTIFICATE_LOGS = "1"

Write-Host "Starting Python test"
python3 -u tests/test_mtls.py
Write-Host "Python test complete"
