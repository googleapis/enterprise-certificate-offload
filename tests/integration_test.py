import ctypes
import faulthandler
import os
import certifi
import google.auth.transport.requests
import requests

from sys import platform
from testing_utils import utils
from unittest import mock

faulthandler.enable()

tests_folder_path = os.path.dirname(os.path.abspath(__file__))
cert_folder = os.path.join(tests_folder_path, os.pardir, "testing_utils", "cert")

# Handling certificates and keys.
ca_cert_file = os.path.join(cert_folder, "ca_cert.pem")
with open(os.path.join(cert_folder, "rsa_cert.pem"), "rb") as f:
    rsa_cert = f.read()
rsa_key_path = os.path.join(cert_folder, "rsa_key.pem")

with open(os.path.join(cert_folder, "ec_cert.pem"), "rb") as f:
    ec_cert = f.read()
ec_key_path = os.path.join(cert_folder, "ec_key.pem")

# Manually set CA cert path to verify local mtls server's cert.
def where():
    return ca_cert_file
certifi.where = where

def get_sign_callback(key_path):
    def sign_callback(sig, sig_len, tbs, tbs_len):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric import ec

        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        data = ctypes.string_at(tbs, tbs_len)
        hash = hashes.Hash(hashes.SHA256())
        hash.update(data)
        digest = hash.finalize()

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=len(digest)),
                hashes.SHA256(),
            )
        else:
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        sig_len[0] = len(signature)
        if sig:
            for i in range(len(signature)):
                sig[i] = signature[i]

        return 1

    return google.auth.transport._custom_tls_signer.SIGN_CALLBACK_CTYPE(sign_callback)

if platform == "win32":
    enterprise_cert_json = utils.generate_win_enterprise_cert_json()
elif platform == "darwin":
    enterprise_cert_json = utils.generate_mac_enterprise_cert_json()
else:
    enterprise_cert_json = utils.generate_linux_enterprise_cert_json()
enterprise_cert_tmp_file = utils.write_enterprise_cert_json(enterprise_cert_json)

def run(cert, key_path):
    with mock.patch("google.auth.transport._custom_tls_signer.get_cert") as get_cert_mock:
        with mock.patch(
            "google.auth.transport._custom_tls_signer.get_sign_callback"
        ) as get_sign_callback_mock:
            get_cert_mock.return_value = cert
            session = requests.Session()
            get_sign_callback_mock.return_value = get_sign_callback(key_path)
            adapter = google.auth.transport.requests._MutualTlsOffloadAdapter(enterprise_cert_tmp_file.name)

            session.mount("https://", adapter)

            r = session.get("https://localhost:3000/foo")
            print(r)

            enterprise_cert_tmp_file.delete

def test_ec():
    run(ec_cert, ec_key_path)

def test_rsa():
    run(rsa_cert, rsa_key_path)