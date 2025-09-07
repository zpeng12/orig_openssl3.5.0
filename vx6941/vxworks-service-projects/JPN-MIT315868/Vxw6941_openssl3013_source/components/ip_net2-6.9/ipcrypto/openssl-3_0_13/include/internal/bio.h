/*
 * Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_BIO_H
# define OSSL_INTERNAL_BIO_H
# pragma once

# include <openssl/core.h>
# include <openssl/bio.h>
# include <openssl/types.h>

struct bio_method_st {
    int type;
    char *name;
    int (*bwrite) (struct bio_st *, const char *, size_t, size_t *);
    int (*bwrite_old) (struct bio_st *, const char *, int);
    int (*bread) (struct bio_st *, char *, size_t, size_t *);
    int (*bread_old) (struct bio_st *, char *, int);
    int (*bputs) (struct bio_st *, const char *);
    int (*bgets) (struct bio_st *, char *, int);
    long (*ctrl) (struct bio_st *, int, long, void *);
    int (*create) (struct bio_st *);
    int (*destroy) (struct bio_st *);
    long (*callback_ctrl) (struct bio_st *, int, int *);
};

void bio_free_ex_data(struct bio_st *bio);
void bio_cleanup(void);


/* Old style to new style BIO_METHOD conversion functions */
int bwrite_conv(struct bio_st *bio, const char *data, size_t datal, size_t *written);
int bread_conv(struct bio_st *bio, char *data, size_t datal, size_t *read);

/* Changes to these internal BIOs must also update include/openssl/bio.h */
# define BIO_CTRL_SET_KTLS                      72
# define BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG     74
# define BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG        75

/*
 * This is used with socket BIOs:
 * BIO_FLAGS_KTLS_TX means we are using ktls with this BIO for sending.
 * BIO_FLAGS_KTLS_TX_CTRL_MSG means we are about to send a ctrl message next.
 * BIO_FLAGS_KTLS_RX means we are using ktls with this BIO for receiving.
 */
# define BIO_FLAGS_KTLS_TX_CTRL_MSG 0x1000
# define BIO_FLAGS_KTLS_RX          0x2000
# define BIO_FLAGS_KTLS_TX          0x4000

/* KTLS related controls and flags */
# define BIO_set_ktls_flag(b, is_tx) \
    BIO_set_flags(b, (is_tx) ? BIO_FLAGS_KTLS_TX : BIO_FLAGS_KTLS_RX)
# define BIO_should_ktls_flag(b, is_tx) \
    BIO_test_flags(b, (is_tx) ? BIO_FLAGS_KTLS_TX : BIO_FLAGS_KTLS_RX)
# define BIO_set_ktls_ctrl_msg_flag(b) \
    BIO_set_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
# define BIO_should_ktls_ctrl_msg_flag(b) \
    BIO_test_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
# define BIO_clear_ktls_ctrl_msg_flag(b) \
    BIO_clear_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)

# define BIO_set_ktls(b, keyblob, is_tx)   \
     BIO_ctrl(b, BIO_CTRL_SET_KTLS, is_tx, keyblob)
# define BIO_set_ktls_ctrl_msg(b, record_type)   \
     BIO_ctrl(b, BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG, record_type, NULL)
# define BIO_clear_ktls_ctrl_msg(b) \
     BIO_ctrl(b, BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG, 0, NULL)

/* Functions to allow the core to offer the CORE_BIO type to providers */
OSSL_CORE_BIO *ossl_core_bio_new_from_bio(struct bio_st *bio);
OSSL_CORE_BIO *ossl_core_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *ossl_core_bio_new_mem_buf(const void *buf, int len);
int ossl_core_bio_read_ex(OSSL_CORE_BIO *cb, void *data, size_t dlen,
                          size_t *readbytes);
int ossl_core_bio_write_ex(OSSL_CORE_BIO *cb, const void *data, size_t dlen,
                           size_t *written);
int ossl_core_bio_gets(OSSL_CORE_BIO *cb, char *buf, int size);
int ossl_core_bio_puts(OSSL_CORE_BIO *cb, const char *buf);
long ossl_core_bio_ctrl(OSSL_CORE_BIO *cb, int cmd, long larg, void *parg);
int ossl_core_bio_up_ref(OSSL_CORE_BIO *cb);
int ossl_core_bio_free(OSSL_CORE_BIO *cb);
int ossl_core_bio_vprintf(OSSL_CORE_BIO *cb, const char *format, va_list args);

int ossl_bio_init_core(struct ossl_lib_ctx_st *libctx, const OSSL_DISPATCH *fns);

#endif
