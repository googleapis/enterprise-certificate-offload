# Copyright 2022 Google LLC.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import json
import os

from sys import platform
from tempfile import NamedTemporaryFile

testing_utils_folder_path = os.path.dirname(os.path.abspath(__file__))
signer_binaries_folder = os.path.join(testing_utils_folder_path, "signer_binaries")
build_folder = os.path.join(testing_utils_folder_path, os.pardir, os.pardir, "build")

def _generate_mac_enterprise_cert_json(issuer):
    if issuer is None:
        issuer = "Google Endpoint Verification"

    cert_info = { "issuer" : issuer }

    libs = {
        "signer_binary": os.path.join(signer_binaries_folder, "mac64", "signer"),
        "signer_library": os.path.join(signer_binaries_folder, "mac64", "signer.dylib"),
        "offload_library": os.path.join(build_folder, "libcertificate_offload.dylib")
    }

    enterprise_cert_dict = {
        "cert_info": cert_info,
        "libs": libs,
        "version": "1"
    }

    return json.dumps(enterprise_cert_dict)

def _generate_win_enterprise_cert_json(issuer):
    return ""

def _generate_linux_enterprise_cert_json(issuer):
    if issuer is None:
        issuer = "Google Endpoint Verification"

    cert_info = { "issuer" : issuer }

    libs = {
        "signer_binary": os.path.join(signer_binaries_folder, "linux64", "signer"),
        "signer_library": os.path.join(signer_binaries_folder, "linux64", "signer.so"),
        "offload_library": os.path.join(build_folder, "libcertificate_offload.so")
    }

    enterprise_cert_dict = {
        "cert_info": cert_info,
        "libs": libs,
        "version": "1"
    }

    return json.dumps(enterprise_cert_dict)

def _write_enterprise_cert_json(contents):
    tmp_file = NamedTemporaryFile(delete=True)
    with open(tmp_file.name, "w") as f:
        f.write(contents)

    return tmp_file

def generate_enterprise_cert_file(issuer = None):
    if platform == "win32":
        enterprise_cert_json = _generate_win_enterprise_cert_json(issuer)
    elif platform == "darwin":
        enterprise_cert_json = _generate_mac_enterprise_cert_json(issuer)
    else:
        enterprise_cert_json = _generate_linux_enterprise_cert_json(issuer)
    return _write_enterprise_cert_json(enterprise_cert_json)
    
