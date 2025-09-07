/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_CORE_H
# define OSSL_INTERNAL_CORE_H
# pragma once

/*
 * namespaces:
 *
 * ossl_method_         Core Method API
 */
# include <openssl/types.h>

/*
 * construct an arbitrary method from a dispatch table found by looking
 * up a match for the < operation_id, name, property > combination.
 * constructor and destructor are the constructor and destructor for that
 * arbitrary object.
 *
 * These objects are normally cached, unless the provider says not to cache.
 * However, force_cache can be used to force caching whatever the provider
 * says (for example, because the application knows better).
 */
typedef struct ossl_method_construct_method_st {
    /* Get a temporary store */
    void *(*get_tmp_store)(void *data);
    /* Reserve the appropriate method store */
    int (*lock_store)(void *store, void *data);
    /* Unreserve the appropriate method store */
    int (*unlock_store)(void *store, void *data);

#ifndef FIPS_MODULE
    /* Get an already existing method from a store */
    void *(*get)(void *store, const struct ossl_provider_st **prov, void *data);
    /* Store a method in a store */
    int (*put)(void *store, void *method, const struct ossl_provider_st *prov,
               const char *name, const char *propdef, void *data);
    /* Construct a new method */
    void *(*construct)(const OSSL_ALGORITHM *algodef, struct ossl_provider_st *prov,
                       void *data);
#endif	
    /* Destruct a method */
    void (*destruct)(void *method, void *data);
} OSSL_METHOD_CONSTRUCT_METHOD;

#ifndef FIPS_MODULE
void *ossl_method_construct(struct ossl_lib_ctx_st *ctx, int operation_id,
                            struct ossl_provider_st **provider_rw, int force_cache,
                            OSSL_METHOD_CONSTRUCT_METHOD *mcm, void *mcm_data);

void ossl_algorithm_do_all(struct ossl_lib_ctx_st *libctx, int operation_id,
                           struct ossl_provider_st *provider,
                           int (*pre)(struct ossl_provider_st *, int operation_id,
                                      int no_store, void *data, int *result),
                           int (*reserve_store)(int no_store, void *data),
                           void (*fn)(struct ossl_provider_st *provider,
                                      const OSSL_ALGORITHM *algo,
                                      int no_store, void *data),
                           int (*unreserve_store)(void *data),
                           int (*post)(struct ossl_provider_st *, int operation_id,
                                       int no_store, void *data, int *result),
                           void *data);
#endif
char *ossl_algorithm_get1_first_name(const OSSL_ALGORITHM *algo);

__owur int ossl_lib_ctx_write_lock(struct ossl_lib_ctx_st *ctx);
__owur int ossl_lib_ctx_read_lock(struct ossl_lib_ctx_st *ctx);
int ossl_lib_ctx_unlock(struct ossl_lib_ctx_st *ctx);
int ossl_lib_ctx_is_child(struct ossl_lib_ctx_st *ctx);
#endif
