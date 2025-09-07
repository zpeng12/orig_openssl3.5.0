/*
 ****************************************************************************
 * 1                    DESCRIPTION
 ****************************************************************************
  This file implements AES-CMAC as per RFC4493  and AES-CMAC-PRF-128 (RFC 4615)
  */

/*
 ****************************************************************************
 * 2                    CONFIGURATION
 ****************************************************************************
 */

#define INCLUDE_AES_CMAC_TESTS


/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */

#include <ipcom_type.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
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

#ifdef __GNUC__
#ifndef alloca
#define alloca __builtin_alloca
#endif
#endif

#define _XOR_BLOCK(out, in1, in2) {int i;for( i = 0; i < AES_BLOCKSIZE; i++ ) out[i] = in1[i] ^ in2[i];}
#define CMAC_SHIFT_LEFT(in, out) {int n; Ip_u8 oflow = 0; for(n=15;n>=0;n--) {        \
                                  out[n] = in[n] << 1; out[n] |= oflow;               \
                                  oflow = (in[n] & 0x80) ? 1 : 0; }}

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
 *===========================================================================
 *                    aesCmacGenerateSubKeys
 *===========================================================================
 * Description: Generates the two CMAC subkeys given an AES 128 bit key
* Parameters:  cmacCtx - pointer to AES_CMAC_CTX.  k1 and k2 and aesKey  are returned via this pointer
*                       key - pointer to the key buffer
*                       keyLengthBits - length of the key in bits
* Modify
*  < cmacCtx->k1 >  - K1 (128-bit first subkey)
*  < cmacCtx->k2 >  - K2 (128-bit first subkey)
*
* Constants: const_Zero is 0x00000000000000000000000000000000
*            const_Rb   is 0x00000000000000000000000000000087
*
*  Variables: L          for output of AES-128 applied to 0^128
*
*    Step 1.  L <- AES-128(K, const_Zero);
*    Step 2.  if MSB(L) is equal to 0
*                K1 <- L << 1;
*             else
*                K1 <- (L << 1) XOR const_Rb;
*    Step 3.  if MSB(K1) is equal to 0
*                K2 <- K1 << 1;
*             else
*                K2 <- (K1 << 1) XOR const_Rb;
*    Step 4.  return K1, K2;
*
* Returns:  1 if success
*                -1 if failure
*
 */
static int aesCmacGenerateSubKeys(AES_CMAC_CTX *cmacCtx,Ip_u8 *key, unsigned int keyLengthBits){

    Ip_u8  L[16],
    Z[16],
    IV[16],
    tmp[16],
    const_Rb[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };

    ipcom_memset( Z, 0, 16 );
    ipcom_memset( L, 0, 16 );
    ipcom_memset( IV, 0, 16 );
    ipcom_memset( cmacCtx->k1, 0, 16 );
    ipcom_memset( cmacCtx->k2, 0, 16 );
    ipcom_memset( cmacCtx->IV, 0, AES_BLOCKSIZE );


    if ( -1 == AES_set_encrypt_key(key, keyLengthBits, &cmacCtx->aesKey)) {
        IPCOM_LOG0(ERR,"AES_set_encrypt_key failed");
        return -1;
    }

    AES_ecb_encrypt(Z, L,&cmacCtx->aesKey, AES_ENCRYPT);

    if ( ( L[0] & 0x80 ) == 0 ) {          /* If MSB(L) == 0, K1 = L << 1 */
        CMAC_SHIFT_LEFT( L, cmacCtx->k1 );
    } else {                               /* if MSB(L) != 0, K1 = ( L << 1 ) (+) Rb */
        CMAC_SHIFT_LEFT( L, tmp );
        _XOR_BLOCK( cmacCtx->k1, tmp, const_Rb );
    }
    if ( ( cmacCtx->k1[0] & 0x80 ) == 0 ) {
        CMAC_SHIFT_LEFT( cmacCtx->k1, cmacCtx->k2 );
    } else {
        CMAC_SHIFT_LEFT( cmacCtx->k1, tmp );
        _XOR_BLOCK( cmacCtx->k2, tmp, const_Rb );
    }

    return 1;
}


/*
 ****************************************************************************
 * 10                   PUBLIC FUNCTIONS
 ****************************************************************************
 */
/*
 *===========================================================================
 *                    aesCmacPrf128
 *===========================================================================
 * Description:  Implements RFC 4615 for IKEv2
 * Parameters:  key - buffer pointing to the variable length key
 *                       keyLength - length of key
 *                      input - pointer to buffer with input message
 *                      inputLength - length of input buffer
 *                      output - pointer to buffer to copy the output to
 *                      outputLength - pointer to length of output buffer.  On input, *outputMacLength must be at least AES_BLOCKSIZE.
*                                                    - on output the length is updated to the actual length of data copied to the output buffer
 * Returns: 1 if success
 *                -1 if any error
 *
 */
IP_EXTERN int aesCmacPrf128(Ip_u8 *key, int keyLength, Ip_u8 *input, int inputLength, Ip_u8 *output, int *outputLength)
{
    Ip_u8 fixedKey[AES_BLOCKSIZE];
    Ip_u8 zerosKey[AES_BLOCKSIZE];
    int fixedKeyLength = AES_BLOCKSIZE;

    if (keyLength != 16)
    {
        ipcom_memset(zerosKey,0,AES_BLOCKSIZE);
        aesCmacBlock(NULL,zerosKey,AES_BLOCKSIZE, key,keyLength, fixedKey,&fixedKeyLength);  /* use CMAC to reduce key to 128 bits */
        key = fixedKey;
        keyLength = fixedKeyLength;
    }
    return aesCmacBlock(NULL,key,keyLength, input,inputLength,output,outputLength);
}

/*
 *===========================================================================
 *                    aesCmacBlock
 *===========================================================================
 * Description:  Calculates AES-CMAC on a complete input buffer
 * Parameters:  cmacCTx - if NULL - no subkeys are returned
*                                        - if !NULL and key != NULL, then the subkeys are calculated and returned in cmacCtx
*                                        - if !NULL and key==NULL, then the subkeys from cmacCtx are used (saving a recalculation)
*                       key - buffer pointing to the variable length key
*                       keyLength - length of key
*                      input - pointer to buffer with input message
*                      inputLength - length of input buffer
*                       output - pointer to buffer to copy the output to
*                       outputMacLength - pointer to length of output buffer.  On input, *outputMacLength must be at least AES_BLOCKSIZE.
*                                                    - on output the length is updated to the actual length of data copied to the output buffer
 * Returns: 1 if success
 *                -1 if any error
 *
 */
IP_EXTERN int aesCmacBlock( AES_CMAC_CTX *cmacCtx,Ip_u8 *key,int keyLength, Ip_u8 *input,int inputLength, Ip_u8 *outputMac,int *outputMacLength)
{
    if (cmacCtx == NULL)
    {
        cmacCtx = alloca(sizeof(AES_CMAC_CTX));
    }
    if (-1 == aesCmacInit(cmacCtx, key, keyLength))
    {
        return -1;
    }
    return aesCmacFinal(cmacCtx,input,inputLength,outputMac,outputMacLength);

}

/*
*===========================================================================
*                    aesCmacInit
*===========================================================================
* Description: Initialize a AES_CMAC_CTX.
* Parameters: cmacCtx - pointer to AES_CMAC_CTX to be updated
*                      key - pointer to key buffer.  If key == NULL, then the AES_CMAC_CTX subkeys are reused.
*                       keyLength - length of key (bytes)
* Returns: 1 on success
*                -1 on error
*
*/
IP_EXTERN int aesCmacInit( AES_CMAC_CTX *cmacCtx, Ip_u8 *key, int keyLength )
{

    /* validate that we either have a key, or a context */
    AES_CMAC_CTX *pCmacCtx = cmacCtx;
    Ip_u8 *pKey = key;

    if ( NULL == pCmacCtx && NULL == key)
    {
        return -1;
    }

    if (NULL == pCmacCtx)
    {
        IPCOM_LOG0(ERR,"aesCmacInit fails, no AES_CMAC_CTX");
        return -1;
    }

    if (NULL != key)
    {
        aesCmacGenerateSubKeys(pCmacCtx,pKey, keyLength <<3);

    }

    /* setup the rest of context */

    pCmacCtx->ivLength = AES_BLOCKSIZE;
    ipcom_memset(pCmacCtx->IV,0,AES_BLOCKSIZE);
    return 1;
}

/*
*===========================================================================
*                    aesCmacUpdate
*===========================================================================
* Description:  Add more data to the CMAC.  Can be called repeatedly with chunks of the message to be authenticated
* Parameters:  cmacCTx -  pointer to AES_CMAC_CTX that has been initialized via aesCmacInit
*                      key - buffer pointint to the variable length key
*                      keyLength - length of key
*                      input - pointer to buffer with input message
*                      inputLength - length of input buffer.  Must be a multiple of AES_BLOCKSIZE
* Returns:
*
*
*/
IP_EXTERN int aesCmacUpdate(AES_CMAC_CTX *cmacCtx, Ip_u8 * input, Ip_u8 inputLength )
{
    /* inputLength must be multiple of the blocksize */
    Ip_u8 *out = alloca(sizeof(Ip_u8 ) * inputLength);

    if (inputLength % AES_BLOCKSIZE==0)
    {
        AES_cbc_encrypt(input, out, inputLength, &cmacCtx->aesKey,cmacCtx->IV, AES_ENCRYPT);
        return 1;
    }
    else
    {
        IPCOM_LOG0(ERR,"aesCmacUpdate, inputLength is not a multiple of the blocksize");
        return -1;
    }
}

/*
 *===========================================================================
 *                    aesCmacFinal
 *===========================================================================
 * Description:  Calculates AES-CMAC on a complete input buffer
 * Parameters:  cmacCtx -  pointer to AES_CMAC_CTX that has been initialized via aesCmacInit
*                      input - pointer to buffer with input message
*                      inputLength - length of input buffer
*                      pMac - pointer to buffer to copy the output MAC to
*                      poutputMacLength - pointer to length of output buffer.  On input, *outputMacLength must be at least AES_BLOCKSIZE.
*                                                    - on output the length is updated to the actual length of data copied to the output buffer
 * Returns: 1 if success
 *                -1 if any error
 */
IP_EXTERN int aesCmacFinal(AES_CMAC_CTX *cmacCtx, Ip_u8 *input, int inputLength,Ip_u8 *pMac,
                 int *pOutputMacLength)
{
    Ip_u8 mlast[AES_BLOCKSIZE], Y[AES_BLOCKSIZE], IV[AES_BLOCKSIZE], *pMn;
    int mlastLength,updateLength;


    if (*pOutputMacLength < AES_BLOCKSIZE)
    {
        IPCOM_LOG0(ERR,"aesCmacFinal fails pMac buffer too small");
        return -1;
    }


    if (inputLength)
    {
        mlastLength = inputLength % AES_BLOCKSIZE;
        if (mlastLength == 0)
        {
            mlastLength = AES_BLOCKSIZE;
        }
        updateLength = inputLength - mlastLength;
    }
    else
    {
        /* a zero length message is a valid concept */
        mlastLength = 0;
        updateLength = 0;
    }
    pMn = &input[updateLength];

    /*
    ** ---- process all but the last block
    */
    if (updateLength)
    {
        aesCmacUpdate(cmacCtx, input, updateLength );
    }

    /*
    ** ---- create M_last (using k1 or k2).
    */
    if ( mlastLength == AES_BLOCKSIZE )
    {
        _XOR_BLOCK( mlast, cmacCtx->k1, pMn );    /* full block - M_last <- K1 XOR M_n; */
    }
    else
    {
        ipcom_memset(Y, 0, AES_BLOCKSIZE);              /* part block - M_last <- padding(M_n) XOR K2 */
        ipcom_memcpy(Y, pMn, mlastLength);
        Y[mlastLength] |= 0x80;
        _XOR_BLOCK( mlast, cmacCtx->k2, Y );
    }

    /*
     ** ---- process M_last to get the MAC into the output buffer
     */

    ipcom_memset (IV, 0, sizeof (IV));
    _XOR_BLOCK( Y, mlast, cmacCtx->IV );                        /* Y <- M_last XOR X  out,in,in */
    AES_ecb_encrypt(Y,pMac, &cmacCtx->aesKey,AES_ENCRYPT);
    *pOutputMacLength = AES_BLOCKSIZE;

    return 1;
}



/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */


