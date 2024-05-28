// Copyright 2022 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
#include <fstream>
#include <iostream>
#include <string>

#include <gtest/gtest.h>
#include <openssl/ssl.h>

#define TEST_RSA_CERT_PATH "tests/testing_utils/cert/rsa_cert.pem"

using SignFunc = int (*)(unsigned char *sig, size_t *sig_len,
                         const unsigned char *tbs, size_t tbs_len);

extern "C" {
  extern int ConfigureSslContext(SignFunc sign_func, const char *cert,
                                  SSL_CTX *ctx);
};

int sign_func_stub(unsigned char *sig, size_t *sig_len,
                         const unsigned char *tbs, size_t tbs_len) {
  return 0;
}

TEST(OffloadTest, ConfigureSslContextNullParams) {
  EXPECT_EQ(ConfigureSslContext(nullptr, nullptr, nullptr), 0);
}

TEST(OffloadTest, ConfigureSslContext) {
  std::ifstream in(TEST_RSA_CERT_PATH);
  std::string contents((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  EXPECT_NE(ctx, nullptr);
  EXPECT_EQ(ConfigureSslContext(&sign_func_stub, contents.c_str(), ctx), 1);
}
