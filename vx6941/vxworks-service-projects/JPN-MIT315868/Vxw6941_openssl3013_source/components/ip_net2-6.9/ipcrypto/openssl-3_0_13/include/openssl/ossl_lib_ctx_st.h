/*#include <crypto/cryptlib.h>*/

#include <openssl/conf.h>
# include <openssl/crypto.h>


#include <openssl/types.h>

#include "internal/thread_once.h"

/*#include "internal/property.h"*/


#include "internal/core.h"


#include "internal/bio.h"
#include "internal/provider.h"

#include "crypto/ctype.h"


#include "crypto/rand.h"


#if 0
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
#endif

#if 0
struct ossl_lib_ctx_st {
    CRYPTO_RWLOCK *lock;
    CRYPTO_EX_DATA data;

    /*
     * For most data in the OSSL_LIB_CTX we just use ex_data to store it. But
     * that doesn't work for ex_data itself - so we store that directly.
     */
    OSSL_EX_DATA_GLOBAL global;

    /* Map internal static indexes to dynamically created indexes */
    int dyn_indexes[OSSL_LIB_CTX_MAX_INDEXES];

    /* Keep a separate lock for each index */
    CRYPTO_RWLOCK *index_locks[OSSL_LIB_CTX_MAX_INDEXES];

    CRYPTO_RWLOCK *oncelock;
    int run_once_done[OSSL_LIB_CTX_MAX_RUN_ONCE];
    int run_once_ret[OSSL_LIB_CTX_MAX_RUN_ONCE];
    struct ossl_lib_ctx_onfree_list_st *onfreelist;
    unsigned int ischild:1;
};
#endif
	
