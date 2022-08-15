# Copyright 2022 Google LLC.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

$OPENSSL_PATH = "C:\OpenSSL-Win64"
$INCLUDE_PATH = $OPENSSL_PATH + "\include"
$LIB_PATH = $OPENSSL_PATH + "\lib"
g++ -fPIC -c .\src\offload.cpp -I $INCLUDE_PATH -m64 -std=c++11
g++ -shared  .\offload.o -o .\build\offload_win64.dll -L $LIB_PATH -I $INCLUDE_PATH -llibcrypto -llibssl -m64 -std=c++11
del offload.o
