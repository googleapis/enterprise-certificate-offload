// Copyright 2023 Google LLC this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
This provider implements ECP (Enterprise Certificate Provider) for OpenSSL. It
provides functions for signing and verifying digital signatures using EC
(Elliptic Curve) and RSA keys. It also provides functions for managing EC and
RSA keys.

Key Features:

* Supports signing and verifying digital signatures using EC and RSA keys
* Provides functions for managing EC and RSA keys
* Supports loading certificates and private keys from ECP storage

To use the ECP provider, you first need to initialize it by calling the
OSSL_provider_init() function. This function will create a provider context that
you can then use to perform signature operations and key management tasks.

ECP_attach_to_ctx can be used to attach the ECP provider to an existing OpenSSL
SSL_CTX object.
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define ECP_API __declspec(dllexport)
#else
#define ECP_API
#endif

#define debug_printf(X)                                                  \
  do {                                                                   \
    if (getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS") != NULL) printf(X); \
  } while (0)

/* RSA signatures are much larger than EC. For EC 72 bytes is probably okay, but
 * it depends on the EC curve. We will hard code to support a 4096 bit RSA key.
 * This is currently the largest practical key for this use case. If the keys or
 * signature get bigger, then this number should be increased to match the max
 * possible signature ECP can create. This is calculated by taking a 4096 bit
 * key, and converting it to bytes e.g. 512 bytes = 4096 bits / 8 bits per byte
 */
#define MAX_SIGNATURE_BUFFER_LEN 512

typedef enum {
  UNKNOWN_KEY_TYPE,
  EC_KEY_TYPE,
  RSA_KEY_TYPE,
} key_types_t;

const char provider_version[] = {"0.1.0"};
const char provider_name[] = {"ECP Provider"};

extern int SignForPython(char *configPath, const unsigned char *dig, int diglen,
                         unsigned char *sig, size_t sigsize);
extern int GetCertPemForPython(char *configPath, char *certHolder,
                               int certHolderLen);
extern char *GetKeyType(char *configPath);

typedef struct ecp_context {
  char *ecp_config_path;
  size_t ecp_config_path_len;
  char *digest_name;
  size_t digest_name_len;
  key_types_t key_type;
  int initialized;
  OSSL_LIB_CTX *libctx;
} ecp_context_t;

static int config_helper(ecp_context_t *ctx, char **ret_config) {
  char *config = getenv("GOOGLE_API_CERTIFICATE_CONFIG");
  if (config == NULL) {
    if (ctx->ecp_config_path == NULL) {
      debug_printf("Unable to determine ECP config path.\n");
      return 0;
    }
    config = ctx->ecp_config_path;
  }
  *ret_config = config;
  return 1;
}

static void *ecp_sign_newctx(void *provctx, const char *propq) {
  debug_printf("Called ecp_sign_newctx\n");
  (void)propq;
  return provctx;
}

static int ecp_sign_init(void *provctx, const char *mdname, void *provkey,
                         const OSSL_PARAM params[]) {
  debug_printf("ecp_sign_init\n");
  (void)provctx;
  (void)mdname;
  (void)provkey;
  (void)params;
  return 1;
}

static int ecp_sign(void *provctx, unsigned char *sigret, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen) {
  debug_printf("Called ecp_sign\n");
  ecp_context_t *ctx = (ecp_context_t *)provctx;
  size_t sig_size_bytes = MAX_SIGNATURE_BUFFER_LEN;

  if (sigret == NULL) {
    *siglen = sig_size_bytes;
    return 1;
  }

  char *config = NULL;
  if (config_helper(ctx, &config) == 0) {
    return 0;
  }

  size_t real_size = SignForPython(config, tbs, tbslen, sigret, sig_size_bytes);
  if (sigsize < real_size) {
    debug_printf("The real signature was too large.\n");
    return 0;
  }

  *siglen = real_size;
  return real_size;
}

static int ecp_dig_sign_init(void *provctx, const char *mdname, void *provkey,
                             const OSSL_PARAM params[]) {
  (void)provkey;
  (void)params;

  debug_printf("Called ecp_dig_sign_init\n");

  ecp_context_t *ctx = (ecp_context_t *)provctx;
  char *supported_mds[] = {"SHA256", "SHA-256", "SHA2-256"};
  for (long unsigned int i = 0; i < sizeof(supported_mds) / sizeof(char *);
       i++) {
    if (strncmp(mdname, supported_mds[i], strlen(supported_mds[i])) == 0) {
      EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, NULL);
      if (md == NULL) {
        return 0;
      }
      EVP_MD_free(md);

      ctx->digest_name_len = strlen(mdname);
      ctx->digest_name = (char *)malloc(sizeof(char) * ctx->digest_name_len);
      strncpy(ctx->digest_name, mdname, ctx->digest_name_len);
      ctx->digest_name[ctx->digest_name_len] = '\0';
      return 1;
    }
  }
  return 0;
}

static int ecp_dig_sign(void *provctx, unsigned char *sigret, size_t *siglen,
                        size_t sigsize, const unsigned char *tbs,
                        size_t tbslen) {
  debug_printf("Called ecp_dig_sign\n");
  ecp_context_t *ctx = (ecp_context_t *)provctx;
  size_t sig_size_bytes = MAX_SIGNATURE_BUFFER_LEN;
  OSSL_LIB_CTX *libctx = ctx->libctx;

  if (sigret == NULL) {
    *siglen = sig_size_bytes;
    debug_printf("Setting siglen\n");
    return 1;
  }

  EVP_MD *md = EVP_MD_fetch(libctx, ctx->digest_name, NULL);
  if (md == NULL) {
    debug_printf("Failed to create md object.\n");
    return 0;
  }

  unsigned char digest[EVP_MAX_MD_SIZE] = {0};
  unsigned int digest_size = 0;

  if (EVP_Digest(tbs, tbslen, digest, &digest_size, md, NULL) != 1) {
    debug_printf("Failed to digest.\n");
    EVP_MD_free(md);
    return 0;
  }

  EVP_MD_free(md);
  char *config = NULL;
  if (config_helper(ctx, &config) == 0) {
    return 0;
  }

  size_t real_size =
      SignForPython(config, digest, digest_size, sigret, sig_size_bytes);
  if (sigsize < real_size) {
    debug_printf("The real signature was too large.");
    return 0;
  }
  *siglen = real_size;
  return real_size;
}

static const OSSL_PARAM *ecp_sign_gettable_ctx_params(void *provctx,
                                                      void *prov) {
  debug_printf("Called ecp_sign_gettable_ctx_params\n");
  (void)provctx;
  (void)prov;

  static const OSSL_PARAM params[] = {
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
      OSSL_PARAM_END,
  };
  return params;
}

static const OSSL_PARAM *ecp_sign_settable_ctx_params(void *provctx,
                                                      void *prov) {
  debug_printf("Called ecp_sign_settable_ctx_params\n");
  (void)provctx;
  (void)prov;

  static const OSSL_PARAM params[] = {
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
      OSSL_PARAM_END,
  };
  return params;
}

static void ecp_sign_freectx(void *provctx) {
  debug_printf("Called ecp_sign_freectx\n");
  (void)provctx;
}

static int ecp_get_params(void *provctx, OSSL_PARAM *params) {
  debug_printf("Called ecp_get_params\n");
  (void)provctx;

  OSSL_PARAM *param = NULL;

  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);

  if (param) {
    return (OSSL_PARAM_set_utf8_ptr(param, provider_name) != 0);
  }

  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
  if (param) {
    return (OSSL_PARAM_set_utf8_ptr(param, provider_version) != 0);
  }

  return 1;
}
static const OSSL_PARAM *ecp_get_table_params(void *provctx) {
  (void)provctx;

  debug_printf("Called ecp_get_table_params\n");
  static const OSSL_PARAM params[] = {
      OSSL_PARAM_DEFN("ecp", OSSL_PARAM_UTF8_PTR, NULL, 0), OSSL_PARAM_END};
  return params;
}

static void ecp_teardown(void *provctx) {
  debug_printf("Called ecp_teardown\n");
  ecp_context_t *ctx = (ecp_context_t *)provctx;
  if (ctx->ecp_config_path != NULL) {
    free(ctx->ecp_config_path);
  }
  free(provctx);
}

static void *ecp_keymgmt_new(void *provctx) {
  debug_printf("Called ecp_keymgmt_new\n");
  (void)provctx;

  return provctx;
}

static void ecp_keymgmt_free(void *provctx) {
  debug_printf("Called ecp_keymgmt_free\n");
  (void)provctx;
}

static void *ecp_keymgmt_load(const void *reference, size_t reference_sz) {
  debug_printf("Called ecp_keymgmt_load\n");
  (void)reference_sz;

  return (void *)reference;
}

static int ecp_keymgmt_has(const void *provctx, int selection) {
  debug_printf("Called ecp_keymgmt_has\n");
  (void)provctx;

  if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
    return 1;
  }
  return 0;
}
static int ecp_keymgmt_match(const void *provctx1, const void *provctx2,
                             int selection) {
  debug_printf("Called ecp_keymgmt_match\n");
  (void)provctx1;
  (void)provctx2;
  (void)selection;

  return 1;
}

static int ec_keymgmt_import(void *provctx, int selection,
                             const OSSL_PARAM params[]) {
  debug_printf("Called ec_keymgmt_import\n");
  (void)provctx;
  (void)selection;
  (void)params;

  return 1;
}

static const OSSL_PARAM *ecp_keymgmt_import_types(int selection) {
  debug_printf("Called ecp_keymgmt_import_types\n");
  (void)selection;

  return NULL;
}

static int ecp_keymgmt_get_params(void *provctx, OSSL_PARAM params[]) {
  debug_printf("Called ecp_keymgmt_get_params\n");
  ecp_context_t *ctx = (ecp_context_t *)provctx;

  char *config = NULL;
  if (config_helper(ctx, &config) == 0) {
    return 0;
  }

  OSSL_PARAM *param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);

  if (param) {
    if (OSSL_PARAM_set_int(param, 256) != 1) {
      return 0;
    }
  }

  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);

  if (param) {
    if (OSSL_PARAM_set_int(param, 239) != 1) {
      return 0;
    }
  }

  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
  if (param) {
    if (OSSL_PARAM_set_int(param, 256) != 1) {
      return 0;
    }
  }

  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
  if (param) {
    if (OSSL_PARAM_set_utf8_string(param, "prime256v1") != 1) {
      return 0;
    }
  }

  return 1;
}

static const OSSL_PARAM *ecp_keymgmt_gettable_params(void *provctx) {
  debug_printf("Called ecp_keymgmt_gettable_params\n");

  (void)provctx;

  static const OSSL_PARAM params[] = {
      OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PAD_MODE, NULL, 0),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
      OSSL_PARAM_END};

  return params;
}
static int ecp_keymgmt_set_params(void *provctx, const OSSL_PARAM params[]) {
  debug_printf("Called ecp_keymgmt_set_params\n");
  (void)provctx;
  (void)params;

  return 1;
}
static const char *ecp_ec_keymgmt_name(int operation_id) {
  debug_printf("Called ecp_ec_keymgmt_name\n");
  (void)operation_id;

  return "EC";
}

static const char *ecp_rsa_keymgmt_name(int operation_id) {
  debug_printf("Called ecp_rsa_keymgmt_name\n");
  (void)operation_id;

  return "RSA";
}

static void *ecp_store_open(void *provctx, const char *uri) {
  debug_printf("Calling ecp_store_open\n");
  ecp_context_t *ctx = (ecp_context_t *)provctx;

  char *config = NULL;
  if (config_helper(ctx, &config) == 0) {
    return 0;
  }

  const char ecp_uri[] = "ecp:";

  if (strncmp(uri, ecp_uri, sizeof(ecp_uri) - 1) == 0) {
    ctx->initialized = 1;

    char *key_type = GetKeyType(config);
    if (strncmp(key_type, "EC", sizeof("EC")) == 0) {
      ctx->key_type = EC_KEY_TYPE;
    } else if (strncmp(key_type, "RSA", sizeof("RSA")) == 0) {
      ctx->key_type = RSA_KEY_TYPE;
    } else {
      ctx->key_type = UNKNOWN_KEY_TYPE;
      return 0;
    }

    return provctx;
  }
  return NULL;
}

const OSSL_PARAM *store_settable_ctx_params(void *provctx) {
  debug_printf("Calling store_settable_ctx_params\n");
  (void)provctx;

  return NULL;
}

static int ecp_store_set_ctx_params(void *provctx, const OSSL_PARAM params[]) {
  debug_printf("Calling ecp_store_set_ctx_params\n");
  (void)provctx;
  (void)params;

  return 1;
}

static int ecp_store_load(void *provctx, OSSL_CALLBACK *object_cb,
                          void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb,
                          void *pw_cbarg) {
  debug_printf("ecp_store_load ecp_store_open\n");
  (void)pw_cb;
  (void)pw_cbarg;

  ecp_context_t *ctx = (ecp_context_t *)provctx;
  int type = OSSL_OBJECT_PKEY;
  char *object_data_type = NULL;
  size_t object_data_type_len = 0;

  if (ctx->key_type == EC_KEY_TYPE) {
    object_data_type = "EC";
    object_data_type_len = sizeof("EC");
  } else if (ctx->key_type == RSA_KEY_TYPE) {
    object_data_type = "RSA";
    object_data_type_len = sizeof("RSA");
  } else {
    return 0;
  }

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &type),
      OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                       object_data_type, object_data_type_len),
      OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &ctx,
                                        sizeof(void *)),
      OSSL_PARAM_construct_end()};

  return object_cb(params, object_cbarg);
}

static int ecp_store_eof(void *provctx) {
  debug_printf("Calling ecp_store_eof\n");
  ecp_context_t *ctx = (ecp_context_t *)provctx;
  if (ctx->initialized == 1) {
    return 0;
  }
  return 1;
}

static int ecp_store_close(void *provctx) {
  debug_printf("Calling ecp_store_close\n");
  (void)provctx;

  return 1;
}

const OSSL_DISPATCH ecp_ec_sign_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ecp_sign_newctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))ecp_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ecp_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))ecp_dig_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))ecp_dig_sign},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ecp_sign_freectx},
    {0, NULL}};

const OSSL_DISPATCH ecp_rsa_sign_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ecp_sign_newctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))ecp_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ecp_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))ecp_dig_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))ecp_dig_sign},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     (void (*)(void))ecp_sign_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
     (void (*)(void))ecp_sign_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))ecp_sign_freectx},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))ecp_sign_freectx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ecp_sign_freectx},
    {0, NULL}};

const OSSL_DISPATCH ecp_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))ecp_store_open},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))ecp_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))ecp_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))ecp_store_close},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))ecp_store_set_ctx_params},
    {0, NULL}};

static const OSSL_DISPATCH ec_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecp_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ecp_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ecp_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ecp_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ecp_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ec_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ecp_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
     (void (*)(void))ecp_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))ecp_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))ecp_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
     (void (*)(void))ecp_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
     (void (*)(void))ecp_ec_keymgmt_name},
    {0, NULL}};

static const OSSL_DISPATCH rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecp_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ecp_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ecp_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ecp_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ecp_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ec_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ecp_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
     (void (*)(void))ecp_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))ecp_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))ecp_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
     (void (*)(void))ecp_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
     (void (*)(void))ecp_rsa_keymgmt_name},
    {0, NULL}};

const OSSL_ALGORITHM ecp_keymgmts[] = {
    {"EC", "provider=ecp", ec_keymgmt_functions, "ECP EC Key Manager"},
    {"RSA", "provider=ecp", rsa_keymgmt_functions, "ECP RSA Key Manager"},
    {NULL, NULL, NULL, NULL}};

OSSL_ALGORITHM ecp_stores[] = {
    {"ecp", "provider=ecp", ecp_store_functions, "ECP Storage functions"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM ecp_signatures[] = {
    {"RSA", "provider=ecp", ecp_rsa_sign_functions, "RSA signature functions"},
    {"EC", "provider=ecp", ecp_ec_sign_functions, "EC signature functions"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM *ecp_query(void *provctx, int operation_id,
                                       int *no_cache) {
  debug_printf("Called ecp_query\n");
  (void)provctx;

  *no_cache = 0;
  switch (operation_id) {
    case OSSL_OP_SIGNATURE:
      debug_printf("signature op\n");
      return ecp_signatures;
    case OSSL_OP_KEYMGMT:
      debug_printf("keymgmt op\n");
      return ecp_keymgmts;
    case OSSL_OP_STORE:
      debug_printf("store op\n");
      return ecp_stores;
  }
  return NULL;
}

const OSSL_DISPATCH ecp_prov_functions[] = {
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ecp_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ecp_query},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))ecp_get_table_params},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ecp_teardown},
    {0, NULL}};

ECP_API const char *ECP_version() { return provider_version; }

ECP_API int ECP_attach_to_ctx(SSL_CTX *ctx, char *ecp_config_path) {
  debug_printf("Called ECP_attach_to_ctx\n");

  char *config = getenv("GOOGLE_API_CERTIFICATE_CONFIG");
  if (config == NULL) {
    config = ecp_config_path;
  }

  X509 *cert = X509_new();
  if (cert == NULL) {
    debug_printf("Unable to create certificate object.\n");
    return 0;
  }

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    debug_printf("Unable to create bio object.\n");
    return 0;
  }
  size_t pem_len = GetCertPemForPython(config, NULL, 0);
  char *pem_bytes = malloc(pem_len);
  pem_len = GetCertPemForPython(config, pem_bytes, pem_len);

  BIO_write(bio, pem_bytes, pem_len);
  cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

  if (cert == NULL) {
    debug_printf("Unable to create certificate object.\n");
    return 0;
  }

  BIO_free(bio);

  if (SSL_CTX_use_certificate(ctx, cert) != 1) {
    debug_printf("Failed to create certificate\n");
  }

  OSSL_STORE_CTX *store = OSSL_STORE_open("ecp:1", NULL, NULL, NULL, NULL);
  if (store == NULL) {
    debug_printf("ECP store was NULL.\n");
    return 0;
  }
  OSSL_STORE_INFO *info = OSSL_STORE_load(store);
  if (info == NULL) {
    debug_printf("ECP store info was NULL.\n");
    return 0;
  }
  EVP_PKEY *privkey = OSSL_STORE_INFO_get1_PKEY(info);
  if (privkey == NULL) {
    debug_printf("ECP privkey was NULL.\n");
    return 0;
  }
  if (SSL_CTX_use_PrivateKey(ctx, privkey) != 1) {
    debug_printf("Failed to create certificate\n");
  }
  return 1;
}

ECP_API int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                               const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out, void **provctx) {
  debug_printf("Called init\n");

  char *config_path = NULL;
  OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
  const OSSL_DISPATCH *dispatch = in;

  for (dispatch = in; dispatch->function_id != 0; dispatch++) {
    if (dispatch->function_id == OSSL_FUNC_CORE_GET_PARAMS) {
      core_get_params = OSSL_FUNC_core_get_params(dispatch);
    }
  }

  OSSL_PARAM params[2] = {
      OSSL_PARAM_construct_utf8_ptr("ecp_config_path", &config_path,
                                    sizeof(config_path)),
      OSSL_PARAM_END};

  if (core_get_params(core, params) == 0) {
    debug_printf("core_get_params failed\n");
    return 0;
  }

  OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_from_dispatch(core, in);
  if (libctx == NULL) {
    return 0;
  }

  ecp_context_t *ctx = malloc(sizeof(ecp_context_t));
  memset(ctx, 0, sizeof(ecp_context_t));

  if (ctx == NULL) {
    return 0;
  }
  ctx->libctx = libctx;

  if (config_path != NULL) {
    ctx->ecp_config_path_len = strlen(config_path);
    ctx->ecp_config_path =
        (char *)malloc(sizeof(char) * ctx->ecp_config_path_len);
    strncpy(ctx->ecp_config_path, config_path, ctx->ecp_config_path_len);
  }

  *out = ecp_prov_functions;
  *provctx = ctx;
  return 1;
}
