/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_PROVIDER_H
# define OPENSSL_PROVIDER_H
# pragma once

# include <openssl/core.h>
# include <openssl/types.h>

# ifdef __cplusplus
extern "C" {
# endif

#if 0
/* Set the default provider search path */
int OSSL_PROVIDER_set_default_search_path(struct ossl_lib_ctx_st *libctx, const char *path);
#endif

/* Load and unload a provider */
struct ossl_provider_st *OSSL_PROVIDER_load(struct ossl_lib_ctx_st *, const char *name);
struct ossl_provider_st *OSSL_PROVIDER_try_load(struct ossl_lib_ctx_st *, const char *name,
                                      int retain_fallbacks);
int OSSL_PROVIDER_unload(struct ossl_provider_st *prov);

#if 0
int OSSL_PROVIDER_available(struct ossl_lib_ctx_st *libctx, const char *name);
#endif

int OSSL_PROVIDER_do_all(struct ossl_lib_ctx_st *ctx,
                         int (*cb)(struct ossl_provider_st *provider, void *cbdata),
                         void *cbdata);

const OSSL_PARAM *OSSL_PROVIDER_gettable_params(const struct ossl_provider_st *prov);
int OSSL_PROVIDER_get_params(const struct ossl_provider_st *prov, OSSL_PARAM params[]);
int OSSL_PROVIDER_self_test(const struct ossl_provider_st *prov);
int OSSL_PROVIDER_get_capabilities(const struct ossl_provider_st *prov,
                                   const char *capability,
                                   OSSL_CALLBACK *cb,
                                   void *arg);

const OSSL_ALGORITHM *OSSL_PROVIDER_query_operation(const struct ossl_provider_st *prov,
                                                    int operation_id,
                                                    int *no_cache);
void OSSL_PROVIDER_unquery_operation(const struct ossl_provider_st *prov,
                                     int operation_id, const OSSL_ALGORITHM *algs);
void *OSSL_PROVIDER_get0_provider_ctx(const struct ossl_provider_st *prov);
const OSSL_DISPATCH *OSSL_PROVIDER_get0_dispatch(const struct ossl_provider_st *prov);

/* Add a built in providers */
int OSSL_PROVIDER_add_builtin(struct ossl_lib_ctx_st *, const char *name,
                              OSSL_provider_init_fn *init_fn);

/* Information */
const char *OSSL_PROVIDER_get0_name(const struct ossl_provider_st *prov);

# ifdef __cplusplus
}
# endif

#endif
