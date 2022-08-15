#!/bin/bash

OPENSSL_PATH="/usr/local/opt/openssl@1.1"
INCLUDE_PATH="$OPENSSL_PATH/include"
LIB_PATH="$OPENSSL_PATH/lib"

g++ -fPIC -c ./src/offload.cpp -I $INCLUDE_PATH -m64 -std=c++11
g++ -shared offload.o -o ./build/offload_mac64.dylib -I $INCLUDE_PATH -L $LIB_PATH -m64 -lcrypto -lssl -std=c++11
rm offload.o
