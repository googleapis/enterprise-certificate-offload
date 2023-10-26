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

FROM ubuntu:22.04
RUN apt update && apt upgrade -y && apt install \
    zsh cmake softhsm2 libp11-kit-dev gnutls-bin opensc curl perl gcc g++ make git jq vim gdb psmisc libffi-dev libreadline6-dev libsqlite3-dev zlib1g-dev patchelf -y
RUN mkdir /work-dir
WORKDIR /work-dir

# Install Go
RUN curl -LO "https://go.dev/dl/go1.21.1.linux-amd64.tar.gz" # TODO: Parameterize go archive.
RUN tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz && rm go1.21.1.linux-amd64.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin"
ENV OPENSSL_ROOT_DIR="/work-dir/openssl"
ENV LD_LIBRARY_PATH="/work-dir/openssl"
ENV OPENSSL_CLI="/work-dir/openssl/apps/openssl"
ENV SOFTHSM2_MODULE="/usr/lib/softhsm/libsofthsm2.so"
ENV ECP_BIN_DIR="/work-dir/bin"

# Build OpenSSL in it's own layer, this is probably the longest part of the build
COPY scripts/openssl_build.sh scripts/openssl_build.sh
RUN zsh ./scripts/openssl_build.sh
# This is to install the global OpenSSL conf. Scripts should be explicit on what OpenSSL is being used.
RUN make -C /work-dir/openssl install -j$(nproc)

# Install Python. This needs the OpenSSL that was built
RUN curl -LO "https://www.python.org/ftp/python/3.11.5/Python-3.11.5.tgz" && tar -xvf Python-3.11.5.tgz
RUN cd Python-3.11.5  && ./configure --with-openssl=/work-dir/openssl && make -j$(nproc) && make install -j$(nproc)


COPY scripts/ scripts/
RUN mkdir -p $ECP_BIN_DIR
RUN zsh ./scripts/ecp_build.sh
RUN zsh ./scripts/create_server_creds.sh
RUN zsh ./scripts/create_client_creds.sh
RUN zsh ./scripts/linux_setup.sh
COPY tests/ tests/
COPY ecp-provider ecp-provider/
RUN cmake -S ecp-provider -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build
RUN patchelf build/libecp_provider.so --replace-needed "/work-dir/ecp-provider/../bin/libecp.so" "libecp.so"
RUN scp ./build/libecp_provider.so $ECP_BIN_DIR
