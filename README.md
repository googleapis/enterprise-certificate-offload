# enterprise-certificate-offload

Repository for the Enterprise Certificate project. This will host C++ source code to offload the TLS signing operation to a signing interface via OpenSSL engine API. The signing interface implementation will be provided by the users. The library will be used by google-auth-library-python library, and distributed as binaries via gCloud SDK.
