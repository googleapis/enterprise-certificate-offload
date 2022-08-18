# enterprise-certificate-offload

Repository for the Enterprise Certificate project. This will host C++ source code to offload the TLS signing operation to a signing interface via OpenSSL engine API. The signing interface implementation will be provided by the users. The library will be used by google-auth-library-python library, and distributed as binaries via gCloud SDK.


### Building

This library is build with CMake. In order to compile the code successfully
please install the following dependencies:

1. CMake
1. OpenSSL 1.1.1

Once the dependencies are installed the library can be built with the following
commands.

#### Linux

```sh
$ cmake -S . -B build # generates build files
$ cmake --build build # compiles the library
```
The binary can now be found at `build/libcertificate_offload.so`.

#### MacOS

```
$ OPENSSL_ROOT_DIR="$(brew --prefix openssl@1.1)" cmake -S . -B build # If OpenSSL is installed via home brew (recommended), specify the OpenSSL root directory with the following command.
$ cmake --build build # compiles the library
```

The binary can now be found at `build/libcertificate_offload.dylib`.

