import faulthandler
import os
from sys import platform

import certifi
import google.auth.transport._custom_tls_signer
import google.auth.transport.requests
import requests

faulthandler.enable()

sample_folder_path = os.path.dirname(os.path.abspath(__file__))
cert_folder = os.path.join(sample_folder_path, os.pardir, os.pardir, "testing", "cert")

def configure_ca_cert():
    ca_cert_file = os.path.join(cert_folder, "ca_cert.pem")

    # Manually set CA cert path to verify local mtls server's cert.
    def where():
        return ca_cert_file
    certifi.where = where

def get_enterprise_cert_file_path():
    if platform == "win32":
        return os.path.join(sample_folder_path, "enterprise_cert_windows.json")
    elif platform == "darwin":
        return os.path.join(sample_folder_path, "enterprise_cert_mac.json")
    return os.path.join(sample_folder_path, "enterprise_cert_linux.json")

def run_sample():
    session = requests.Session()
    file_path = get_enterprise_cert_file_path()
    signer = google.auth.transport._custom_tls_signer.CustomTlsSigner(file_path)
    signer.load_libraries()
    signer.set_up_custom_key()
    adapter = google.auth.transport.requests._MutualTlsOffloadAdapter(signer)

    session.mount("https://", adapter)

    r = session.get("https://localhost:3000/foo")
    print(r)


if __name__ == "__main__":
    configure_ca_cert()
    run_sample()