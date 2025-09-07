/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_TYPES_H
# define OPENSSL_TYPES_H
# pragma once

# include <limits.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/e_os2.h>
# include <openssl/safestack.h>
# include <openssl/macros.h>


# include <openssl/core.h>


# include "internal/refcount.h"



#if 0
# include <internal/cryptlib.h>
#include "../crypto/evp/evp_local.h"
#endif
#if 0
#include "crypto/evp.h"
#endif

/*#include "internal/ffc.h"*/


/* OSSL_LIB_CTX */

# define OSSL_LIB_CTX_PROVIDER_STORE_RUN_ONCE_INDEX          0
# define OSSL_LIB_CTX_DEFAULT_METHOD_STORE_RUN_ONCE_INDEX    1
# define OSSL_LIB_CTX_METHOD_STORE_RUN_ONCE_INDEX            2
# define OSSL_LIB_CTX_MAX_RUN_ONCE                           3

# define OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX         0
# define OSSL_LIB_CTX_PROVIDER_STORE_INDEX           1
# define OSSL_LIB_CTX_PROPERTY_DEFN_INDEX            2
# define OSSL_LIB_CTX_PROPERTY_STRING_INDEX          3
# define OSSL_LIB_CTX_NAMEMAP_INDEX                  4
# define OSSL_LIB_CTX_DRBG_INDEX                     5
# define OSSL_LIB_CTX_DRBG_NONCE_INDEX               6
# define OSSL_LIB_CTX_RAND_CRNGT_INDEX               7
# ifdef FIPS_MODULE
#  define OSSL_LIB_CTX_THREAD_EVENT_HANDLER_INDEX    8
# endif
# define OSSL_LIB_CTX_FIPS_PROV_INDEX                9
# define OSSL_LIB_CTX_ENCODER_STORE_INDEX           10
# define OSSL_LIB_CTX_DECODER_STORE_INDEX           11
# define OSSL_LIB_CTX_SELF_TEST_CB_INDEX            12
# define OSSL_LIB_CTX_BIO_PROV_INDEX                13
# define OSSL_LIB_CTX_GLOBAL_PROPERTIES             14
# define OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX      15
# define OSSL_LIB_CTX_PROVIDER_CONF_INDEX           16
# define OSSL_LIB_CTX_BIO_CORE_INDEX                17
# define OSSL_LIB_CTX_CHILD_PROVIDER_INDEX          18
# define OSSL_LIB_CTX_MAX_INDEXES                   19


# define CRYPTO_EX_INDEX__COUNT_MAX          18




typedef struct crypto_ex_data_st CRYPTO_EX_DATA;


typedef void CRYPTO_EX_new (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp);
typedef void CRYPTO_EX_free (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                           void **from_d, int idx, long argl, void *argp);

#ifndef EX_CALLBACKS
/*
 * Each structure type (sometimes called a class), that supports
 * exdata has a stack of callbacks for each instance.
 */
struct ex_callback_st {
    long argl;                  /* Arbitrary long */
    void *argp;                 /* Arbitrary void * */
    int priority;               /* Priority ordering for freeing */
    CRYPTO_EX_new *new_func;
    CRYPTO_EX_free *free_func;
    CRYPTO_EX_dup *dup_func;
};

typedef struct ex_callbacks_st {
    STACK_OF(EX_CALLBACK) *meth;
} EX_CALLBACKS;
#endif

#ifndef CRYPTO_RWLOCK
typedef void CRYPTO_RWLOCK;
#endif

#ifndef OSSL_EX_DATA_GLOBAL
typedef struct ossl_ex_data_global_st {
    CRYPTO_RWLOCK *ex_data_lock;
    EX_CALLBACKS ex_data[CRYPTO_EX_INDEX__COUNT_MAX];
}OSSL_EX_DATA_GLOBAL;
#endif

#ifndef OSSL_PROVIDER
typedef struct ossl_provider_st	OSSL_PROVIDER;
#endif

#if 0
#ifndef OSSL_PROVIDER
struct ossl_provider_st {
    /* Flag bits */
    unsigned int flag_initialized:1;
    unsigned int flag_activated:1;
    unsigned int flag_fallback:1; /* Can be used as fallback */

    /* Getting and setting the flags require synchronization */
    CRYPTO_RWLOCK *flag_lock;

    /* OpenSSL library side data */
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *refcnt_lock;  /* For the ref counter */
    int activatecnt;
    char *name;
    char *path;
    struct dso_st *module;
    OSSL_provider_init_fn *init_function;
    STACK_OF(INFOPAIR) *parameters;
    struct ossl_lib_ctx_st *libctx; /* The library context this instance is in */
    struct provider_store_st *store; /* The store this instance belongs to */
#ifndef FIPS_MODULE
    /*
     * In the FIPS module inner provider, this isn't needed, since the
     * error upcalls are always direct calls to the outer provider.
     */
    int error_lib;     /* ERR library number, one for each provider */
# ifndef OPENSSL_NO_ERR
    struct ERR_string_data_st *error_strings; /* Copy of what the provider gives us */
# endif
#endif

    /* Provider side functions */
    OSSL_FUNC_provider_teardown_fn *teardown;
    OSSL_FUNC_provider_gettable_params_fn *gettable_params;
    OSSL_FUNC_provider_get_params_fn *get_params;
    OSSL_FUNC_provider_get_capabilities_fn *get_capabilities;
    OSSL_FUNC_provider_self_test_fn *self_test;
    OSSL_FUNC_provider_query_operation_fn *query_operation;
    OSSL_FUNC_provider_unquery_operation_fn *unquery_operation;

    /*
     * Cache of bit to indicate of query_operation() has been called on
     * a specific operation or not.
     */
    unsigned char *operation_bits;
    size_t operation_bits_sz;
    CRYPTO_RWLOCK *opbits_lock;

#ifndef FIPS_MODULE
    /* Whether this provider is the child of some other provider */
    const OSSL_CORE_HANDLE *handle;
    unsigned int ischild:1;
#endif

    /* Provider side data */
    void *provctx;
    const OSSL_DISPATCH *dispatch;
};
typedef struct ossl_provider_st OSSL_PROVIDER; /* Provider Object */
#endif
#endif

# ifdef NO_ASN1_TYPEDEFS
#  define ASN1_INTEGER            ASN1_STRING
#  define ASN1_ENUMERATED         ASN1_STRING
#  define ASN1_BIT_STRING         ASN1_STRING
#  define ASN1_OCTET_STRING       ASN1_STRING
#  define ASN1_PRINTABLESTRING    ASN1_STRING
#  define ASN1_T61STRING          ASN1_STRING
#  define ASN1_IA5STRING          ASN1_STRING
#  define ASN1_UTCTIME            ASN1_STRING
#  define ASN1_GENERALIZEDTIME    ASN1_STRING
#  define ASN1_TIME               ASN1_STRING
#  define ASN1_GENERALSTRING      ASN1_STRING
#  define ASN1_UNIVERSALSTRING    ASN1_STRING
#  define ASN1_BMPSTRING          ASN1_STRING
#  define ASN1_VISIBLESTRING      ASN1_STRING
#  define ASN1_UTF8STRING         ASN1_STRING
#  define ASN1_BOOLEAN            int
#  define ASN1_NULL               int
# else
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;
# endif

typedef struct asn1_type_st ASN1_TYPE;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_string_table_st ASN1_STRING_TABLE;

typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef struct asn1_pctx_st ASN1_PCTX;
typedef struct asn1_sctx_st ASN1_SCTX;

# ifdef _WIN32
#  undef X509_NAME
#  undef X509_EXTENSIONS
#  undef PKCS7_ISSUER_AND_SERIAL
#  undef PKCS7_SIGNER_INFO
#  undef OCSP_REQUEST
#  undef OCSP_RESPONSE
# endif

# ifdef BIGNUM
#  undef BIGNUM
# endif

#if 0
typedef struct bio_st BIO;
#endif

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;
typedef struct buf_mem_st BUF_MEM;

STACK_OF(BIGNUM);
STACK_OF(BIGNUM_const);

typedef struct err_state_st ERR_STATE;

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct engine_st ENGINE;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

struct evp_md_ctx_st {
    const EVP_MD *reqdigest;    /* The original requested digest */
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (struct evp_md_ctx_st *ctx, const void *data, size_t count);

    /*
     * Opaque ctx returned from a providers digest algorithm implementation
     * OSSL_FUNC_digest_newctx()
     */
    void *algctx;
    EVP_MD *fetched_digest;
} /* EVP_MD_CTX */ ;
typedef struct evp_md_ctx_st EVP_MD_CTX;

typedef struct evp_mac_st EVP_MAC;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;
typedef struct evp_pkey_st EVP_PKEY;

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;

typedef struct evp_pkey_method_st EVP_PKEY_METHOD;

typedef struct evp_keymgmt_st EVP_KEYMGMT;

typedef struct evp_kdf_st EVP_KDF;
typedef struct evp_kdf_ctx_st EVP_KDF_CTX;

typedef struct evp_rand_st EVP_RAND;
typedef struct evp_rand_ctx_st EVP_RAND_CTX;

typedef struct evp_keyexch_st EVP_KEYEXCH;

typedef struct evp_signature_st EVP_SIGNATURE;

typedef struct evp_asym_cipher_st EVP_ASYM_CIPHER;

typedef struct evp_kem_st EVP_KEM;

#if 1
typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;
#endif

typedef struct hmac_ctx_st HMAC_CTX;

typedef struct dh_st DH;
typedef struct dh_method DH_METHOD;

# ifndef OPENSSL_NO_DEPRECATED_3_0
#if 0
struct dsa_st {
    /*
     * This first variable is used to pick up errors where a DSA is passed
     * instead of of a EVP_PKEY
     */
    int pad;
    int32_t version;
    FFC_PARAMS params;
    BIGNUM *pub_key;            /* y public key */
    BIGNUM *priv_key;           /* x private key */
    int flags;
    /* Normally used to cache montgomery values */
    BN_MONT_CTX *method_mont_p;
    CRYPTO_REF_COUNT references;
#ifndef FIPS_MODULE
    CRYPTO_EX_DATA ex_data;
#endif
    const DSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    CRYPTO_RWLOCK *lock;
    OSSL_LIB_CTX *libctx;

    /* Provider data */
    size_t dirty_cnt; /* If any key material changes, increment this */
};
#endif

typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;
# endif

# ifndef OPENSSL_NO_DEPRECATED_3_0
typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;
# endif
typedef struct rsa_pss_params_st RSA_PSS_PARAMS;

# ifndef OPENSSL_NO_DEPRECATED_3_0
typedef struct ec_key_st EC_KEY;
typedef struct ec_key_method_st EC_KEY_METHOD;
# endif

typedef struct rand_meth_st RAND_METHOD;
typedef struct rand_drbg_st RAND_DRBG;

typedef struct ssl_dane_st SSL_DANE;
typedef struct x509_st X509;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct x509_crl_method_st X509_CRL_METHOD;
typedef struct x509_revoked_st X509_REVOKED;
typedef struct X509_name_st X509_NAME;
typedef struct X509_pubkey_st X509_PUBKEY;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;

typedef struct x509_object_st X509_OBJECT;
typedef struct x509_lookup_st X509_LOOKUP;
typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;

typedef struct x509_sig_info_st X509_SIG_INFO;

typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

typedef struct v3_ext_ctx X509V3_CTX;
typedef struct conf_st CONF;
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;

typedef struct ui_st UI;
typedef struct ui_method_st UI_METHOD;


typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

typedef struct comp_ctx_st COMP_CTX;
typedef struct comp_method_st COMP_METHOD;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct DIST_POINT_st DIST_POINT;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;



typedef struct ossl_http_req_ctx_st OSSL_HTTP_REQ_CTX;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_responder_id_st OCSP_RESPID;

typedef struct sct_st SCT;
typedef struct sct_ctx_st SCT_CTX;
typedef struct ctlog_st CTLOG;
typedef struct ctlog_store_st CTLOG_STORE;
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

typedef struct ossl_store_info_st OSSL_STORE_INFO;
typedef struct ossl_store_search_st OSSL_STORE_SEARCH;

typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

typedef struct ossl_dispatch_st OSSL_DISPATCH;

typedef struct ossl_item_st OSSL_ITEM;

typedef struct ossl_algorithm_st OSSL_ALGORITHM;
typedef struct ossl_param_st OSSL_PARAM;
typedef struct ossl_param_bld_st OSSL_PARAM_BLD;

typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);

typedef struct ossl_encoder_st OSSL_ENCODER;
typedef struct ossl_encoder_ctx_st OSSL_ENCODER_CTX;
typedef struct ossl_decoder_st OSSL_DECODER;
typedef struct ossl_decoder_ctx_st OSSL_DECODER_CTX;

typedef struct ossl_self_test_st OSSL_SELF_TEST;


#ifdef  __cplusplus
}
#endif

#endif /* OPENSSL_TYPES_H */
