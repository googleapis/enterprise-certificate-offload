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


### Testing

#### Test Dependencies

The [Enterprise Certificate Proxy](https://github.com/googleapis/enterprise-certificate-proxy)
is an integration test dependency for this library.

In order for the integration tests to pass the binaries from enterprise-certificate-proxy must first be compiled.
To do this run `$ ./scripts/setup_signer_proxy.sh`. This will fetch the current tip of the
enterprise-certificate-proxy repo, compile it, and move the binaries to where
the tests are expecting them.

#### Integration Tests

The integration tests for the `enterprise-certificate-offload` are in the
`tests/integration_test.py` file.

To run the integration tests, run `$ ./scripts/integration_test.sh`.

Alternatively, the integration tests can manually be run by following these
steps:

#### Install Python dependencies.

First (optionally) create a virtual environment.

```
pyenv virtualenv myenv
pyenv local myenv
```

Then install the dependencies
```
python -m pip install -r requirements.txt
```

To debug the offload library, set `GOOGLE_AUTH_TLS_OFFLOAD_LOGGING=1`.

#### Run a local mTLS server

There are 2 methods to start a local mTLS server using the testing certs:

Method 1: In the root folder of this repo run the golang server
```
go run -v ./tests/testing_utils/server/server.go
```
It listens to `https://localhost:3000/foo`.

Method 2: Navigate to `./testing/cert` folder, and start an OpenSSL s_server
```
openssl s_server -cert rsa_cert.pem -key rsa_key.pem -CAfile ca_cert.pem -WWW -port 3000 -verify_return_error -Verify 1
```

#### Run the integration test

After completing the previous two steps, run `$ python -m pytest tests/test.py`.
