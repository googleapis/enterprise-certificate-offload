import json
import os

from tempfile import NamedTemporaryFile

testing_utils_folder_path = os.path.dirname(os.path.abspath(__file__))
signer_binaries_folder = os.path.join(testing_utils_folder_path, "signer_binaries")
build_folder = os.path.join(testing_utils_folder_path, os.pardir, "build")

def generate_mac_enterprise_cert_json():
    cert_info = { "issuer" : "not used" }

    libs = {
        "signer_binary": os.path.join(signer_binaries_folder, "mac64", "signer"),
        "signer_library": os.path.join(signer_binaries_folder, "mac64", "signer.dylib"),
        "offload_library": os.path.join(build_folder, "offload_mac64.dylib")
    }

    enterprise_cert_dict = {
        "cert_info": cert_info,
        "libs": libs,
        "version": "1"
    }

    return json.dumps(enterprise_cert_dict)

def generate_win_enterprise_cert_json():
    return ""

def generate_linux_enterprise_cert_json():
    return ""

def write_enterprise_cert_json(contents):
    tmp_file = NamedTemporaryFile(delete=True)
    with open(tmp_file.name, "w") as f:
        f.write(contents)

    return tmp_file
    
