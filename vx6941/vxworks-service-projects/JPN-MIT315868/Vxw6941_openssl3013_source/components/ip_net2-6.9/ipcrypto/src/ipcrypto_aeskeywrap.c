/*
 ****************************************************************************
 * 1                    DESCRIPTION
 ****************************************************************************
  This file implements AES-KEYWRAP as per RFC 3394
  */

/*
 ****************************************************************************
 * 2                    CONFIGURATION
 ****************************************************************************
 */


/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */

#include <sys/types.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ipcom_syslog.h>
#include <ipcrypto.h>
#include "ipcrypto_h.h"


/*
 ****************************************************************************
 * 4                    EXTERN PROTOTYPES
 ****************************************************************************
 */


/*
 ****************************************************************************
 * 5                    DEFINES
 ****************************************************************************
 */

#define AES_CHECK_KEYLEN(len)   ((len==AES_KEY_128_BYTES)||(len==AES_KEY_192_BYTES)||(len==AES_KEY_256_BYTES))

#define AESKW_WRAP_MIN_BLOCK    2
#define AESKW_UNWRAP_MIN_BLOCK  (AESKW_WRAP_MIN_BLOCK+1)
#define AESKW_XOR_BLOCK(out, in1, in2) {int ijk;for( ijk = 0; ijk < AESKW_BLOCKSIZE; ijk++ ) out[ijk] = in1[ijk] ^ in2[ijk];}
#define AESKW_CVT(b,n)  {ipcom_memset(b,0,AESKW_BLOCKSIZE);b[AESKW_BLOCKSIZE-1] = ((n)&0xFF);b[AESKW_BLOCKSIZE-2] = (((n)&0xFF00)>>8);\
b[AESKW_BLOCKSIZE-3] = (((n)&0xFF0000)>>16);b[AESKW_BLOCKSIZE-4] = (((n)&0xFF000000)>>24);}



/*
 ****************************************************************************
 * 6                    TYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 7                    LOCAL PROTOTYPES
 ****************************************************************************
 */

/*
****************************************************************************
* 8                    DATA
****************************************************************************
*/


/*
 ****************************************************************************
 * 9                    LOCAL FUNCTIONS
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 10                   PUBLIC FUNCTIONS
 ****************************************************************************
 */

/*
 *===========================================================================
 *                    aeskw_wrap
 *===========================================================================
 * Description: Encrypt (wrap) a key using AES-KEYWRAP
 * Parameters:  key - pointer to key buffer
 *                       keyLength - length of key,  must be 128 bit, 192 bit or 256 bit (in bytes)
 *                       iv - pointer to IV.
 *                      ivLength - length of IV.  Must be AESKW_BLOCKSIZE
 *                      plainText - pointer to buffer to encrypt (wrap)
 *                      plainTextLength - length of buffer to encrypt.  Must be multiple of AESKW_BLOCKSIZE
 *                      cipherText - pointer to buffer in which to copy output
 *                      cipherTextLength - pointer to the length of the cipherText buffer.  On output,
 *                                                     this is updated to the length of data copied into the cipherText buffer
  * Returns: -1 if failure
 *
 */
IP_EXTERN int aeskw_wrap(Ip_u8 *key, int keyLength,
                          Ip_u8 *iv, int ivLength,
                          Ip_u8 *plainText, int plainTextLength,
                          Ip_u8 *cipherText, int *cipherTextLength )
{
    int status = 1;
    AES_KEY aesKey;

    /*
    ** --- Check for proper key length
    */
    if (AES_CHECK_KEYLEN(keyLength))
    {
        /*
        ** --- Check for proper IV length
        */
        if (ivLength == AESKW_BLOCKSIZE)
        {
            /*
            ** --- Make sure the input is aligned to 64-bit boundaries
            */
            if ( !(plainTextLength % AESKW_BLOCKSIZE) )
            {

                /*
                ** --- Make sure the output buffer is at least
                **     one block (64-bits) larger than the input.
                */
                if (*cipherTextLength >= (plainTextLength+AESKW_BLOCKSIZE))
                {
                    int numBlocks = plainTextLength/AESKW_BLOCKSIZE;
                    Ip_u8 *R;
                    Ip_u8 A[AESKW_BLOCKSIZE];
                    Ip_u8 B[AES_BLOCKSIZE];
                    Ip_u8 T[AESKW_BLOCKSIZE];
                    int i,j;

                    if (numBlocks >= AESKW_WRAP_MIN_BLOCK)
                    {
                        /*
                        ** --- Set output buffer size
                        */
                        *cipherTextLength = plainTextLength+AESKW_BLOCKSIZE;

                        /*
                        ** --- Initialize variables
                        **
                        **          Set A = IV, an initial value (see 2.2.3)
                        **          For i = 1 to n
                        **          R[i] = P[i]
                        */
                        ipcom_memcpy(A, iv, AESKW_BLOCKSIZE);
                        R = cipherText + AESKW_BLOCKSIZE;
                        ipcom_memcpy( R, plainText, plainTextLength );

                        if ( -1 == AES_set_encrypt_key(key, keyLength << 3,&aesKey)) {
                            IPCOM_LOG0(ERR,"AES_set_encrypt_key failed");
                            return -1;
                        }


                        for ( j = 0; j < 6; j++ )
                        {
                            for ( i = 0; i < numBlocks; i++ )
                            {
                                /*
                                ** --- Do: B = AES(K, A | R[i])
                                ** --- Do: R[i] = LSB(64, B)
                                */
                                ipcom_memcpy( B + AESKW_BLOCKSIZE, R + (i * AESKW_BLOCKSIZE), AESKW_BLOCKSIZE);
                                ipcom_memcpy( B, A, AESKW_BLOCKSIZE);

                                AES_ecb_encrypt(B,B, &aesKey,AES_ENCRYPT);
                                /* ccip_aes_encrypt( CCI_MODE_ECB, key, keyLength, B, AES_BLOCKSIZE, B, NULL ); */

                                ipcom_memcpy( A, B, AESKW_BLOCKSIZE);
                                ipcom_memcpy( R + (i * AESKW_BLOCKSIZE), B + AESKW_BLOCKSIZE, AESKW_BLOCKSIZE);

                                /*
                                ** --- Do: A = MSB(64, B) ^ t where t = (n*j)+i
                                */
                                AESKW_CVT(T,(numBlocks*j)+(i+1));
                                AESKW_XOR_BLOCK(A,T,A);
                            }
                        }

                        /*
                        ** --- Do: Set C[0] = A
                        */
                        ipcom_memcpy( cipherText, A, AESKW_BLOCKSIZE);
                    }
                    else
                    {
                        status = -1;
                        IPCOM_LOG0(ERR,"Keywrap: outputBuffer too small\n");
                    }
                }
                else
                {
                    status = -1;
                    IPCOM_LOG0(ERR,"Keywrap: message too short\n");
                }
            }
            else
            {
                status = -1;
                IPCOM_LOG0(ERR,"Keywrap: input buffer not a multiple of the blocksize");
            }
        }
        else
        {
            status = -1;
            IPCOM_LOG0(ERR,"Keywrap: invalid blocksize");
        }
    }
    else
    {
        status = -1;
        IPCOM_LOG0(ERR,"Keywrap: invalid keylength");
    }
    return( status );
}
/*
 *===========================================================================
 *                    aeskw_unwrap
 *===========================================================================
 * Description: Decrypt (unwrap) a key using AES-KEYWRAP
 * Parameters:  key - pointer to key buffer
 *                       keyLength - length of key,  must be 128 bit, 192 bit or 256 bit (in bytes)
 *                       iv - pointer to IV.
 *                      ivLength - length of IV.  Must be AESKW_BLOCKSIZE
 *                      cipherText - pointer to buffer to decrypt (unwrap)
 *                      cipherTextLength - length of buffer to decrypt.  Must be multiple of AESKW_BLOCKSIZE
 *                      plainText - pointer to buffer in which to copy output
 *                      plainTextLength - pointer to the length of the plainText buffer.  On output,
 *                                                     this is updated to the length of data copied into the plainText buffer
  * Returns: -1 if failure
 *
 */
IP_EXTERN  int aeskw_unwrap(Ip_u8 *key, int keyLength,
                             Ip_u8 *iv, int ivLength,
                             Ip_u8 *cipherText, int cipherTextLength,
                             Ip_u8 *plainText, int *plainTextLength)
{
    int status = 1;
    AES_KEY aesKey;


    /*
    ** --- Check for proper key length
    */
    if (AES_CHECK_KEYLEN(keyLength))
    {
        /*
        ** --- Check for proper IV length
        */
        if (ivLength == AESKW_BLOCKSIZE)
        {
            /*
            ** --- Make sure the input is aligned to 64-bit boundaries
            */
            if ( !(cipherTextLength % AESKW_BLOCKSIZE) )
            {

                /*
                ** --- Make sure the output buffer is at least
                **     one block (64-bits) smaller than the input
                */
                if (*plainTextLength >= (cipherTextLength-AESKW_BLOCKSIZE))
                {
                    int numBlocks = (cipherTextLength/AESKW_BLOCKSIZE)-1;
                    Ip_u8 *R, *A;
                    Ip_u8 B[AES_BLOCKSIZE];
                    Ip_u8 T[AESKW_BLOCKSIZE];
                    int i,j;

                    if ((numBlocks+1) >= AESKW_UNWRAP_MIN_BLOCK)
                    {
                        /*
                        ** --- Set output buffer size
                        */
                        *plainTextLength = cipherTextLength-AESKW_BLOCKSIZE;

                        /*
                        ** --- Initialize variables
                        **
                        **		Set A = C[0]
                        **		For i = 1 to n
                        **			R[i] = C[i]
                        */
                        A = cipherText;
                        R = plainText;
                        ipcom_memcpy( R, cipherText + AESKW_BLOCKSIZE, cipherTextLength-AESKW_BLOCKSIZE );

                        if ( -1 == AES_set_decrypt_key(key, keyLength << 3,&aesKey)) {
                            IPCOM_LOG0(ERR,"AES_set_decrypt_key failed");
                            return -1;
                        }


                        for ( j = 6; j > 0; j-- )
                        {
                            for ( i = numBlocks; i > 0; i-- )
                            {
                                /*
                                ** --- Do: (A ^ t)
                                */
                                AESKW_CVT(T,((numBlocks)*(j-1))+(i));
                                AESKW_XOR_BLOCK(A,T,A);

                                /*
                                ** --- Do: B = AES(K, A | R[i])
                                ** --- Do: R[i] = LSB(64, B)
                                */
                                ipcom_memcpy( B + AESKW_BLOCKSIZE, R + ((i-1) * AESKW_BLOCKSIZE), AESKW_BLOCKSIZE);
                                ipcom_memcpy( B, A, AESKW_BLOCKSIZE);
                                AES_ecb_encrypt(B, B,&aesKey, AES_DECRYPT);

                                ipcom_memcpy( A, B, AESKW_BLOCKSIZE);
                                ipcom_memcpy( R + ((i-1)  * AESKW_BLOCKSIZE), B + AESKW_BLOCKSIZE, AESKW_BLOCKSIZE);
                            }
                        }

                        /*
                        ** --- Make sure the first block is equal to the IV
                        */
                        if (ipcom_memcmp( A, iv, AESKW_BLOCKSIZE))
                        {
                            status = -1;
                            IPCOM_LOG0(ERR,"Keyunwrap: decoding error");
                        }
                    }
                    else
                    {
                        IPCOM_LOG0(ERR,"Keyunwrap:message too short");
                        status = -1;
                    }
                }
                else
                {
                    status = -1;
                    IPCOM_LOG0(ERR,"keyunwrap: output buffer too small");
                }
            }
            else
            {
                IPCOM_LOG0(ERR,"keyunwrap: input buffer not a multiple of the blocksize");
                status = -1;
            }
        }
        else
        {
            IPCOM_LOG0(ERR,"keyunwrap: invalid iv length");
            status = -1;
        }
    }
    else
    {
        IPCOM_LOG0(ERR,"invalid key length");
        status = -1;
    }

    return( status );
}
/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */






