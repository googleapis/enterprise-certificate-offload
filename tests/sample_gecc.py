# Copyright 2022 Google LLC.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import faulthandler
import google.auth
import sys

from google.auth.transport import requests
from sys import platform

from testing_utils import utils

# sys.path.insert(0, '../testing_utils')
# from .. import testing_utils
faulthandler.enable()

creds, _ = google.auth.default()
project = "sijunliu-dca-test"

def run_sample():
    enterprise_cert_tmp_file = utils.generate_enterprise_cert_file()
    adapter = requests._MutualTlsOffloadAdapter(enterprise_cert_tmp_file.name)
    authed_session = requests.AuthorizedSession(creds)
    authed_session.mount("https://", adapter)
    response = authed_session.request("GET", f"https://pubsub.mtls.googleapis.com/v1/projects/{project}/topics")
    enterprise_cert_tmp_file.delete
    print(response)

if __name__ == "__main__":
    run_sample()
    print("done")
