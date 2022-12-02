// Copyright 2022 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cstddef>
#include <iostream>
#include <memory>

namespace {

using SignFunc = int (*)(unsigned char *sig, size_t *sig_len,
                         const unsigned char *tbs, size_t tbs_len);

class CustomKey {
 public:
  explicit CustomKey(SignFunc sign_func) : sign_func_(sign_func) {}

  bool Sign(unsigned char *sig, size_t *sig_len, const unsigned char *tbs,
            size_t tbs_len) {
    return sign_func_(sig, sig_len, tbs, tbs_len);
  }

 public:
  SignFunc sign_func_;
};

template <typename T, typename Ret, Ret (*Deleter)(T *)>
struct OpenSSLDeleter {
  void operator()(T *t) const { Deleter(t); }
};
struct OpenSSLFreeDeleter {
  void operator()(unsigned char *buf) const { OPENSSL_free(buf); }
};
template <typename T, void (*Deleter)(T *)>
using OwnedOpenSSLPtr = std::unique_ptr<T, OpenSSLDeleter<T, void, Deleter>>;
template <typename T, int (*Deleter)(T *)>
using OwnedOpenSSLPtrIntRet =
    std::unique_ptr<T, OpenSSLDeleter<T, int, Deleter>>;
using OwnedBIO = OwnedOpenSSLPtrIntRet<BIO, BIO_free>;
using OwnedENGINE = OwnedOpenSSLPtrIntRet<ENGINE, ENGINE_free>;
using OwnedEVP_MD_CTX = OwnedOpenSSLPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using OwnedEVP_PKEY = OwnedOpenSSLPtr<EVP_PKEY, EVP_PKEY_free>;
using OwnedEVP_PKEY_METHOD =
    OwnedOpenSSLPtr<EVP_PKEY_METHOD, EVP_PKEY_meth_free>;
using OwnedSSL_CTX = OwnedOpenSSLPtr<SSL_CTX, SSL_CTX_free>;
using OwnedSSL = OwnedOpenSSLPtr<SSL, SSL_free>;
using OwnedX509_PUBKEY = OwnedOpenSSLPtr<X509_PUBKEY, X509_PUBKEY_free>;
using OwnedX509 = OwnedOpenSSLPtr<X509, X509_free>;
using OwnedOpenSSLBuffer = std::unique_ptr<uint8_t, OpenSSLFreeDeleter>;

// Logging utils.
bool g_enable_logging = false;
void LogInfo(const std::string &message) {
  if (g_enable_logging) {
    std::cout << "tls_offload.cpp: " << message << "...." << std::endl;
  }
}

// Part 1. First we need a way to attach `CustomKey` to `EVP_PKEY`s that we will
// hand to OpenSSL. OpenSSL does this with "ex data". The following
// `SetCustomKey` and `GetCustomKey` provide the setter and getter methods.

// "ex data" will be allocated once globally by `CreateEngineOnceGlobally`
// method.
int g_rsa_ex_index = -1, g_ec_ex_index = -1;

void FreeExData(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
                void *argp) {
  // CustomKey is created by ConfigureSslContext, so we need to delete the
  // CustomKey stored in ex_data.
  if (g_enable_logging) {
    std::cout << "deleting custom_key at: " << ptr << std::endl;
  }
  delete static_cast<CustomKey *>(ptr);
}

bool SetCustomKey(EVP_PKEY *pkey, CustomKey *key) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    LogInfo("setting RSA custom key");
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa && RSA_set_ex_data(rsa, g_rsa_ex_index, key);
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    LogInfo("setting EC custom key");
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    return ec_key && EC_KEY_set_ex_data(ec_key, g_ec_ex_index, key);
  }
  return false;
}

CustomKey *GetCustomKey(EVP_PKEY *pkey) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa ? static_cast<CustomKey *>(RSA_get_ex_data(rsa, g_rsa_ex_index))
               : nullptr;
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    return ec_key ? static_cast<CustomKey *>(
                        EC_KEY_get_ex_data(ec_key, g_ec_ex_index))
                  : nullptr;
  }
  return nullptr;
}

// Part 2. Next we make an `EVP_PKEY_METHOD` that can call `CustomKey::Sign`.

// As OpenSSL sets up an `EVP_PKEY_CTX`, it will configure it with
// `EVP_PKEY_CTRL_*` calls. This structure collects all the values.
struct OpenSSLParams {
  const EVP_MD *md = nullptr;
  int rsa_padding = RSA_PKCS1_PADDING;
  int rsa_pss_salt_len = -2;
  const EVP_MD *rsa_pss_mgf1_md = nullptr;
};

int CustomInit(EVP_PKEY_CTX *ctx) {
  EVP_PKEY_CTX_set_data(ctx, new OpenSSLParams);
  return 1;
}

void CustomCleanup(EVP_PKEY_CTX *ctx) {
  OpenSSLParams *params =
      static_cast<OpenSSLParams *>(EVP_PKEY_CTX_get_data(ctx));
  delete params;
}

int CustomCtrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  OpenSSLParams *params =
      static_cast<OpenSSLParams *>(EVP_PKEY_CTX_get_data(ctx));
  // `EVP_PKEY_CTRL_*` values correspond to `EVP_PKEY_CTX` APIs. See
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_get_signature_md.html
  switch (type) {
    case EVP_PKEY_CTRL_MD:  // EVP_PKEY_CTX_set_signature_md
      params->md = static_cast<const EVP_MD *>(p2);
      return 1;
    case EVP_PKEY_CTRL_GET_MD:  // EVP_PKEY_CTX_get_signature_md
      *static_cast<const EVP_MD **>(p2) = params->md;
      return 1;
    case EVP_PKEY_CTRL_RSA_PADDING:  // EVP_PKEY_CTX_set_rsa_padding
      params->rsa_padding = p1;
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_PADDING:  // EVP_PKEY_CTX_get_rsa_padding
      *static_cast<int *>(p2) = params->rsa_padding;
      return 1;
    case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:  // EVP_PKEY_CTX_set_rsa_pss_saltlen
      params->rsa_pss_salt_len = p1;
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:  // EVP_PKEY_CTX_get_rsa_pss_saltlen
      *static_cast<int *>(p2) = params->rsa_pss_salt_len;
      return 1;
    case EVP_PKEY_CTRL_RSA_MGF1_MD:  // EVP_PKEY_CTX_set_rsa_mgf1_md
      // OpenSSL never actually configures this and relies on the default, but
      // it is, in theory, part of the PSS API.
      params->rsa_pss_mgf1_md = static_cast<const EVP_MD *>(p2);
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:  // EVP_PKEY_CTX_get_rsa_mgf1_md
      // If unspecified, the MGF-1 digest defaults to the signing digest.
      *static_cast<const EVP_MD **>(p2) =
          params->rsa_pss_mgf1_md ? params->rsa_pss_mgf1_md : params->md;
      return 1;
  }
  if (g_enable_logging) {
    std::cout << "unrecognized EVP ctrl value:" << type << std::endl;
  }
  return 0;
}

// This function will call CustomKey::Sign to sign the digest of tbs (the bytes
// to be signed) and write back to sig (the signature holder). The supported
// algorithms are:
// (1) ECDSA with SHA256
// (2) RSAPSS with SHA256, MGF-1, salt length = digest length
int CustomDigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *sig_len,
                     const unsigned char *tbs, size_t tbs_len) {
  EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(ctx);

  // Grab the custom key.
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
  if (!pkey) {
    LogInfo("Could not get EVP_PKEY");
    return 0;
  }
  CustomKey *key =
      GetCustomKey(EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx)));
  if (!key) {
    LogInfo("Could not get CustomKey from EVP_PKEY");
    return 0;
  }

  // For signature scheme, we only support
  // (1) ECDSA with SHA256
  // (2) RSAPSS with SHA256, MGF-1, salt length = digest length
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    const EVP_MD *md;
    if (EVP_PKEY_CTX_get_signature_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported ECDSA hash");
      return 0;
    }
  } else if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    const EVP_MD *md;
    if (EVP_PKEY_CTX_get_signature_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported ECDSA hash");
      return 0;
    }
    int val;
    if (EVP_PKEY_CTX_get_rsa_padding(pctx, &val) != 1 ||
        val != RSA_PKCS1_PSS_PADDING) {
      LogInfo("Unsupported RSA padding");
      return 0;
    }
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported RSA-PSS MGF-1 hash");
      return 0;
    }
    // The salt length could either be specified explicitly, or as -1.
    if (EVP_PKEY_CTX_get_rsa_pss_saltlen(pctx, &val) != 1 ||
        (val != EVP_MD_size(md) && val != -1)) {
      LogInfo("Unsupported RSA-PSS salt length");
      return 0;
    }
  } else {
    LogInfo("Unsupported key");
    return 0;
  }

  if (g_enable_logging) {
    std::cout << "before calling key->Sign, sig len: " << *sig_len << std::endl;
  }
  int res = key->Sign(sig, sig_len, tbs, tbs_len);
  if (g_enable_logging) {
    std::cout << "after calling key->Sign, sig len: " << *sig_len
              << ", result: " << res << std::endl;
  }
  return res;
}

// Each `EVP_PKEY_METHOD` is associated with a key type, so we must make a
// separate one for each.
OwnedEVP_PKEY_METHOD MakeCustomMethod(int nid) {
  OwnedEVP_PKEY_METHOD method(EVP_PKEY_meth_new(
      nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM | EVP_PKEY_FLAG_AUTOARGLEN));
  if (!method) {
    return nullptr;
  }

  EVP_PKEY_meth_set_init(method.get(), CustomInit);
  EVP_PKEY_meth_set_cleanup(method.get(), CustomCleanup);
  EVP_PKEY_meth_set_ctrl(method.get(), CustomCtrl, nullptr);
  EVP_PKEY_meth_set_digestsign(method.get(), CustomDigestSign);
  return method;
}

// Part 3. OpenSSL doesn't pick up our `EVP_PKEY_METHOD` unless it is wrapped in
// an `ENGINE`. We don't `ENGINE_add` this engine, to avoid it accidentally
// overriding normal keys.

// These variables will be created once globally by `CreateEngineOnceGlobally`.
EVP_PKEY_METHOD *g_custom_rsa_pkey_method, *g_custom_ec_pkey_method;

int EngineGetMethods(ENGINE *e, EVP_PKEY_METHOD **out_method,
                     const int **out_nids, int nid) {
  if (!out_method) {
    static const int kNIDs[] = {EVP_PKEY_EC, EVP_PKEY_RSA};
    *out_nids = kNIDs;
    return sizeof(kNIDs) / sizeof(kNIDs[0]);
  }

  switch (nid) {
    case EVP_PKEY_EC:
      *out_method = g_custom_ec_pkey_method;
      return 1;
    case EVP_PKEY_RSA:
      *out_method = g_custom_rsa_pkey_method;
      return 1;
  }
  return 0;
}

// Part 4. Now we can make custom `EVP_PKEY`s that wrap our `CustomKey` objects.
// Note we require the caller provide the public key, here in a certificate.
// This is necessary so OpenSSL knows how much to size its various buffers.

OwnedEVP_PKEY MakeCustomEvpPkey(CustomKey *custom_key, X509 *cert,
                                ENGINE *custom_engine) {
  unsigned char *spki = nullptr;
  int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spki);
  if (spki_len < 0) {
    return nullptr;
  }
  OwnedOpenSSLBuffer owned_spki(spki);

  const unsigned char *ptr = spki;
  OwnedX509_PUBKEY pubkey(d2i_X509_PUBKEY(nullptr, &ptr, spki_len));
  if (!pubkey) {
    return nullptr;
  }

  OwnedEVP_PKEY wrapped(X509_PUBKEY_get(pubkey.get()));
  if (!wrapped || !EVP_PKEY_set1_engine(wrapped.get(), custom_engine) ||
      !SetCustomKey(wrapped.get(), custom_key)) {
    return nullptr;
  }
  return wrapped;
}

// Part 5. Now we can attach the CustomKey and cert to SSL context.

bool AttachKeyCertToSslContext(CustomKey *custom_key, const char *cert,
                               SSL_CTX *ctx, ENGINE *custom_engine) {
  OwnedBIO bio(BIO_new_mem_buf(cert, strlen(cert)));
  if (!bio) {
    LogInfo("failed to read cert into bio");
    return false;
  }
  OwnedX509 x509 =
      OwnedX509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));

  OwnedEVP_PKEY wrapped_key =
      MakeCustomEvpPkey(custom_key, x509.get(), custom_engine);
  if (!wrapped_key) {
    LogInfo("failed to create custom key");
    return false;
  }

  static const char *sig_algs_list = "RSA-PSS+SHA256:ECDSA+SHA256";
  if (!SSL_CTX_set1_sigalgs_list(ctx, sig_algs_list)) {
    LogInfo("failed to call SSL_CTX_set1_sigalgs_list");
    return false;
  }
  if (!SSL_CTX_use_PrivateKey(ctx, wrapped_key.get())) {
    LogInfo("SSL_CTX_use_PrivateKey failed");
    return false;
  }
  if (!SSL_CTX_use_certificate(ctx, x509.get())) {
    LogInfo("SSL_CTX_use_certificate failed");
    return false;
  }
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    LogInfo("SSL_CTX_set_min_proto_version failed");
    return false;
  }
  LogInfo("AttachKeyCertToSslContext is successful");
  return true;
}

// Part 6. The following functions create a OpenSSL engine, during which all the
// `g_*` global variables such as `g_rsa/ec_ex_index`,
// `g_custom_rsa/ec_pkey_method` etc will be initialized. Note that
// `CreateEngineOnceGlobally` should be used because it creates all these global
// variables and the engine only once, and it is thread safe.

ENGINE *CreateEngineHelper() {
  g_enable_logging =
      static_cast<bool>(getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS"));
  LogInfo("Creating engine...");

  // Allocate "ex data". We need a way to attach `CustomKey` to `EVP_PKEY`s that
  // we will hand to OpenSSL. OpenSSL does this with "ex data"
  g_rsa_ex_index =
      RSA_get_ex_new_index(0, nullptr, nullptr, nullptr, FreeExData);
  g_ec_ex_index =
      EC_KEY_get_ex_new_index(0, nullptr, nullptr, nullptr, FreeExData);
  if (g_rsa_ex_index < 0 || g_ec_ex_index < 0) {
    LogInfo("Error allocating ex data");
    return nullptr;
  }

  // Create custom method
  g_custom_rsa_pkey_method = MakeCustomMethod(EVP_PKEY_RSA).release();
  g_custom_ec_pkey_method = MakeCustomMethod(EVP_PKEY_EC).release();
  if (!g_custom_rsa_pkey_method || !g_custom_ec_pkey_method) {
    LogInfo("failed to make custom methods");
    return nullptr;
  }

  // Ceate a custom engine
  OwnedENGINE engine(ENGINE_new());
  if (!engine || !ENGINE_set_pkey_meths(engine.get(), EngineGetMethods)) {
    LogInfo("failed to init engine");
    return nullptr;
  }
  return engine.release();
}

ENGINE *CreateEngineOnceGlobally() {
  static ENGINE *custom_engine = CreateEngineHelper();
  return custom_engine;
}

}  // namespace

// Part 7. The function below is exported to the compiled shared library
// binary. For all these function, we need to add `extern "C"` to avoid name
// mangling, and `__declspec(dllexport)` for Windows.
// Note that the caller owns the memory for all the pointers passed in as a
// parameter, and caller is responsible for freeing these memories.

// Configure the SSL context to use the provide client side cert and custom key.
extern "C"
#ifdef _WIN32
    __declspec(dllexport)
#endif
        int ConfigureSslContext(SignFunc sign_func, const char *cert,
                                SSL_CTX *ctx) {
  if (!sign_func) {
    return 0;
  }

  if (!cert) {
    return 0;
  }

  if (!ctx) {
    return 0;
  }

  ENGINE *custom_engine = CreateEngineOnceGlobally();
  if (!custom_engine) {
    LogInfo("failed to create engine");
    return 0;
  }

  // The created custom_key will be deleted by FreeExData.
  CustomKey *custom_key = new CustomKey(sign_func);
  if (g_enable_logging) {
    std::cout << "created custom_key at: " << custom_key << std::endl;
  }

  if (!AttachKeyCertToSslContext(custom_key, cert, ctx, custom_engine)) {
    return 0;
  }
  LogInfo("ConfigureSslContext is successful");
  return 1;
}
