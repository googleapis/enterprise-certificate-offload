#!/bin/python3

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

import ctypes
import ssl
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from requests.packages.urllib3.poolmanager import PoolManager
import pathlib
import sys
import os

print("Starting test.")

server_port = os.environ.get("MTLS_SERVER_PORT", 8888)
cert_config = os.environ.get("GOOGLE_API_CERTIFICATE_CONFIG_PATH")
provider_path = os.environ.get("PROVIDER_PATH")

def create_ecp_ffi():

  ecp_lib = ctypes.CDLL(provider_path)
  ecp_lib.ECP_attach_to_ctx.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
  ecp_lib.ECP_attach_to_ctx.restype = ctypes.c_int

  return ecp_lib

class ECPAdapter(HTTPAdapter):
  def init_poolmanager(self, connections, maxsize, block=False, *args, **kwargs):
    context = create_urllib3_context()
    ctx = ctypes.c_void_p.from_address(id(context) + ctypes.sizeof(ctypes.c_void_p) * 2)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    ecp_lib = create_ecp_ffi()
    print(f"Loaded cffi {ecp_lib=}")
    attach_to_ctx_return_code = ecp_lib.ECP_attach_to_ctx(ctx, cert_config.encode('ascii'))
    print(f'{attach_to_ctx_return_code=}')

    kwargs['ssl_context'] = context
    self.poolmanager = PoolManager(
        num_pools=connections, maxsize=maxsize,
        block=block, *args, **kwargs)

try:
  s = requests.Session()
  s.mount("https://127.0.0.1", ECPAdapter())
  res = s.get(f"https://127.0.0.1:{server_port}/input.txt", verify=False)
  data = res.text
  print(f'Received: {data}')
  assert data == "hello world\n"
except Exception as e:
  print(f"Test failed due to {e}")
  sys.exit(1)

print("Test passed")
sys.exit(0)
