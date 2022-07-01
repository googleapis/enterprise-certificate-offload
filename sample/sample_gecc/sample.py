import faulthandler
import os
from sys import platform

from google.auth.transport import _custom_tls_signer, requests
import google.auth

faulthandler.enable()

creds, _ = google.auth.default()
project = "sijunliu-dca-test"

sample_folder_path = os.path.dirname(os.path.abspath(__file__))

def get_enterprise_cert_file_path():
    if platform == "win32":
        return os.path.join(sample_folder_path, "enterprise_cert_windows.json")
    elif platform == "darwin":
        return os.path.join(sample_folder_path, "enterprise_cert_mac.json")
    return os.path.join(sample_folder_path, "enterprise_cert_linux.json")

def run_sample():
    file_path = get_enterprise_cert_file_path()
    signer = google.auth.transport._custom_tls_signer.CustomTlsSigner(file_path)
    signer.load_libraries()
    signer.set_up_custom_key()
    adapter = requests._MutualTlsOffloadAdapter(signer)
    authed_session = requests.AuthorizedSession(creds)
    authed_session.mount("https://", adapter)
    response = authed_session.request("GET", f"https://pubsub.mtls.googleapis.com/v1/projects/{project}/topics")
    print(response)

if __name__ == "__main__":
    run_sample()
    print("done")