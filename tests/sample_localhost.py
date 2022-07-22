import faulthandler
import imp
import google.auth
import sys
import os
import certifi
import requests
import google.auth.transport.requests
from sys import platform

from testing_utils import utils

# sys.path.insert(0, '../testing_utils')
# from .. import testing_utils
faulthandler.enable()

sample_folder_path = os.path.dirname(os.path.abspath(__file__))
cert_folder = os.path.join(sample_folder_path, "testing_utils", "cert")

def configure_ca_cert():
    ca_cert_file = os.path.join(cert_folder, "ca_cert.pem")

    # Manually set CA cert path to verify local mtls server's cert.
    def where():
        return ca_cert_file
    certifi.where = where

def run_sample():
    enterprise_cert_tmp_file = utils.generate_enterprise_cert_file(issuer="CertReq Test Root")
    adapter = google.auth.transport.requests._MutualTlsOffloadAdapter(enterprise_cert_tmp_file.name)
    session = requests.Session()
    session.mount("https://", adapter)
    response = session.get("https://localhost:3000/foo")
    enterprise_cert_tmp_file.delete
    print(response)

if __name__ == "__main__":
    configure_ca_cert()
    run_sample()
    print("done")