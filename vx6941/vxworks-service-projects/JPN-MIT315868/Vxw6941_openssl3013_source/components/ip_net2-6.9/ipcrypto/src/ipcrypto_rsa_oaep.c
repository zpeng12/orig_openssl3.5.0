#define IPCOM_USE_CLIB_PROTO
#include <ipcom_clib.h>
#include <ipcrypto_config.h>
#include <ipcom_type.h>
#include <ipcom_cstyle.h>
#include <ipcom_err.h>

#include <openssl/evp.h>

/*
 *===========================================================================
 *                    ipcrypto_oaep_mask
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
static void
ipcrypto_oaep_mask(const EVP_MD* hash,
                Ip_u8* seed,
                int seed_len,
                Ip_u8* data,
                int data_len)

{
    unsigned count = 0;

    ip_assert(EVP_MD_size(hash) <= EVP_MAX_MD_SIZE);

    while (data_len > 0) {
        int i, max = (data_len > EVP_MD_size(hash) ? EVP_MD_size(hash) : data_len);
        EVP_MD_CTX md_ctx;
        unsigned char counter[4], hash_buf[EVP_MAX_MD_SIZE];
        unsigned int hash_size = sizeof(hash_buf);


        IP_SET_HTONL(counter, count);

        EVP_MD_CTX_init(&md_ctx);
        EVP_DigestInit(&md_ctx, hash);
        EVP_DigestUpdate(&md_ctx, seed, seed_len);
        EVP_DigestUpdate(&md_ctx, counter, 4);
        EVP_DigestFinal(&md_ctx, hash_buf, &hash_size);
        count++;

        for (i = 0; i < max; i++)
            data[i] ^= hash_buf[i];

        data += max;
        data_len -= max;
    }
}


/*
 *===========================================================================
 *                    ipcrypto_rsa_oaep
 *===========================================================================
 * Description:

                             +----------+---------+-------+
                        DB = |  lHash   |    PS   |   M   |
                             +----------+---------+-------+
                                            |
                  +----------+              V
                  |   seed   |--> MGF ---> xor
                  +----------+              |
                        |                   |
               +--+     V                   |
               |00|    xor <----- MGF <-----|
               +--+     |                   |
                 |      |                   |
                 V      V                   V
               +--+----------+----------------------------+
         EM =  |00|maskedSeed|          maskedDB          |
               +--+----------+----------------------------+
 * Parameters:
 *
 * Returns:
 *
 */
IP_GLOBAL void
ipcrypto_rsa_oaep_encode(const EVP_MD* hash,
                         unsigned char *in,
                         int inlen,
                         unsigned char *out,
                         int outlen)
{
    int k = outlen; /* length in octets of the RSA modulus */
    int i;
    const int hLen = EVP_MD_size(hash);
    unsigned int md_size;

    /* The length of the input data must be at most k - 2hLen - 2. */
    ip_assert(inlen > 0 && inlen <= k - 2*hLen - 2);

    /* Leading byte zero. */
    out[0] = 0;
    /* At position 1, the seed: hLen bytes of random data. */
    for (i = 1; i < hLen+1; i+=4)
    {
        Ip_u32 rnd;
        rnd = ipcom_random();
        if ((hLen+1)-i >=4)
            ipcom_memcpy(&out[i], &rnd, 4);
        else
            ipcom_memcpy(&out[i], &rnd, (hLen+1)-i);
    }
    /* The data block DB starts at position 1+hLen, consisting of: */
    /* The hash of the label (only an empty label supported) */
    EVP_Digest(IP_NULL, 0, &out[1+hLen], &md_size, hash, IP_NULL);
    /* Zero octets padding */
    ipcom_memset(out + 2*hLen + 1, 0, outlen - (2*hLen + 1));
    /* A single 1 octet, thereafter the input message data. */
    out[outlen - inlen - 1] = 1;
    ipcom_memcpy(out + outlen - inlen, in, inlen);

    /* Use the seed data to mask the block DB with the seed data */
    ipcrypto_oaep_mask(hash, out+1, hLen, out+hLen+1, outlen-hLen-1);

    /* Mask the masked DB with the seed. */
    ipcrypto_oaep_mask(hash, out+hLen+1, outlen-hLen-1, out+1, hLen);
}


/*
 *===========================================================================
 *                    ipcrypto_rsa_oaep_decode
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_GLOBAL Ip_err
ipcrypto_rsa_oaep_decode(const EVP_MD* hash,
                         unsigned char *in,
                         int in_len,
                         unsigned char *out,
                         int* out_len)
{
    const int hLen = EVP_MD_size(hash);
    int pos;

    /* Unmask seed */
    ipcrypto_oaep_mask(hash, in+1+hLen, in_len-(1+hLen), in+1, hLen);

    /* Unmask cleartext message, using seed */
    ipcrypto_oaep_mask(hash, in+1, hLen, in+1+hLen, in_len-(1+hLen));

    /* Proceed past section of null padding */
    pos = 2*hLen+1;
    while (in[pos] == 0 && pos < in_len)
        pos++;
    if (in[pos] != 1 || pos > in_len-1)
        return IPCOM_ERR_INVALID_ARG;
    pos++; /* Proceed past '1' byte */

    if (*out_len < in_len-pos-1)
        return IPCOM_ERR_INVALID_ARG;

    *out_len = in_len-pos;
    ipcom_memcpy(out, &in[pos], *out_len);

    return IPCOM_SUCCESS;
}
