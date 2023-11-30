# Introduction

This repo contains an implementation of an OpenSSL provider. This provider only
supports signature operations using [ECP](https://github.com/googleapis/enterprise-certificate-proxy).

The provider is coded to tightly integrate with ECP and generally various
algorithms will be hard coded.

The primary use of this library is by the google-auth-library-python library.

# Getting Started

## Starting point

The GitHub actions document how to build, test, and run this provider. The
simplest to start from is the Linux CI, as all the complexity is in Docker.

## Required Dependencies

The scripts in this repo require `zsh`.

## Linux

### **Recommended** Setup (Docker)

A development environment can be bootstrapped using docker.

#### Build a docker image

```
$ sudo docker build -t ecp-build -f utils/linux/Dockerfile .
```

#### Run test suites in docker image

```
$ sudo docker run ecp-build zsh -c '/work-dir/scripts/start_mtls_server.sh && for test in /work-dir/tests/*; do zsh $test; done'
```

#### Work in docker image

```
$ sudo docker run -t ecp-build -it /bin/zsh
```


# Testing

Tests are stored in the `tests` directory. Only integration tests exist. They
test that the Provider works in the following scenarios:

1. OpenSSL to OpenSSL mTLS. An OpenSSL server will be spun up that requires
   client verification. The OpenSSL client will be used to connect to the
   server, using ECP backed credentials.
1. Python to OpenSSL mTLS. An OpenSSL server will be spun up that requires
   client verification. The Python `request` library will be used to connect to the
   server, using ECP backed credentials, and submit a HTTPS request.
