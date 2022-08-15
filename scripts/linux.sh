# Copyright 2022 Google LLC.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

#!/bin/bash

g++ -fPIC -c ./src/offload.cpp -m64 -std=c++11
g++ -shared offload.o -o ./build/offload_linux64.so -m64 -lcrypto -lssl -std=c++11
rm offload.o
