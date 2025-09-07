/*
 ******************************************************************************
 *                     INTERPEAK SOURCE FILE
 *
 *   Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto_cmd_aeskeywrap_test.c,v $ $Revision: 1.1 $
 *   $Source: /home/interpeak/CVSRoot/ipcrypto/src/ipcrypto_cmd_aeskeywrap_test.c,v $
 *   $Author: roger $
 *   $State: Exp $ $Locker:  $
 *
 *   Copyright 2000-2007 Interpeak AB (http://www.interpeak.se). All rights reserved.
 *   Design and implementation by FirstName LastName <email@interpeak.se>
 ******************************************************************************
 */


/*
 ****************************************************************************
 * 1                    DESCRIPTION
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 2                    CONFIGURATION
 ****************************************************************************
 */

#include "ipcrypto_config.h"


/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */
#define IPCOM_USE_CLIB_PROTO
#include <ipcom_type.h>
#include <ipcom_cstyle.h>
#include <ipcom_clib.h>

#include "ipcrypto.h"
#include "ipcrypto_h.h"


/*
 ****************************************************************************
 * 4                    DEFINES
 ****************************************************************************
 */
#define VALIDATE_TEST_RESULT(expected,actual,length,description) \
                if(ipcom_memcmp(expected,actual,length)!= 0) \
                { \
                    ipcom_printf("%s Failed\n",description); \
                    show_buffer("Expected",expected,length,16); \
                    show_buffer("Actual",actual,length,16); \
                    return -1; \
                } \
                else \
                { \
                    ipcom_printf("%s Passed\n",description); \
                }


/*
 ****************************************************************************
 * 5                    TYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 6                    EXTERN PROTOTYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 7                    LOCAL PROTOTYPES
 ****************************************************************************
 */

IP_STATIC void show_buffer( char *title,     void *buffer,     int length,     int lineLen );
IP_GLOBAL int ipcrypto_cmd_aeskeywrap_test(int argc, char **argv);

/*
 ****************************************************************************
 * 8                    DATA
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 9                    STATIC FUNCTIONS
 ****************************************************************************
 */

IP_STATIC void
show_buffer(char *title,
            void *buffer,
            int length,
            int lineLen)
{
    char *ptr = (char *)buffer;
    int i, rowLen = 0, colLen = 0, llen;

    if ( ptr && length )
    {
        if ( !lineLen ) lineLen = 16;

        llen = (lineLen * 3) + 6 + (((lineLen/4) + 1) * 2);
        ipcom_printf("\n\n( %s ) (%u-bytes, %u-bits)\n", title, length, (length*8));
        for ( i = 0; i < llen; i++ ) ipcom_printf("*");

        ipcom_printf("\n %04X :: ", rowLen++);
        for ( i = 0; i < length; i++ )
        {
            ipcom_printf("%02X ", (unsigned char)ptr[i] );
            colLen++;

            if (colLen && !(colLen%4) && (colLen != lineLen))
                ipcom_printf("| ");

            if ((colLen == lineLen) & (i!=(length-1)))
            {
                colLen = 0;
                ipcom_printf("\n %04X :: ", rowLen * lineLen);
                rowLen++;
            }
        }

        ipcom_printf("\n");
        for ( i = 0; i < llen; i++ ) ipcom_printf("*");
        ipcom_printf("\n");
    }
}



/*
 ****************************************************************************
 * 10                   GLOBAL FUNCTIONS
 ****************************************************************************
 */

IP_GLOBAL int
ipcrypto_cmd_aeskeywrap_test(int argc, char **argv)
{
    Ip_u8 orig_iv[] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6};
    Ip_u8 kek[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
    Ip_u8 keydata[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    Ip_u8 ciphertext_key128_keydata128[] = {0x1F,0xA6,0x8B,0x0A,0x81,0x12,0xB4,0x47,0xAE,0xF3,0x4B,0xD8,0xFB,0x5A,0x7B,0x82,0x9D,0x3E,0x86,0x23,0x71,0xD2,0xCF,0xE5};
    Ip_u8 ciphertext_key192_keydata128[] = {0x96,0x77,0x8B,0x25,0xAE,0x6C,0xA4,0x35,0xF9,0x2B,0x5B,0x97,0xC0,0x50,0xAE,0xD2,0x46,0x8A,0xB8,0xA1,0x7A,0xD8,0x4E,0x5D};
    Ip_u8 ciphertext_key256_keydata128[] = {0x64,0xE8,0xC3,0xF9,0xCE,0x0F,0x5B,0xA2,0x63,0xE9,0x77,0x79,0x05,0x81,0x8A,0x2A,0x93,0xC8,0x19,0x1E,0x7D,0x6E,0x8A,0xE7};
    Ip_u8 ciphertext_key192_keydata_192[] = {0x03,0x1D,0x33,0x26,0x4E,0x15,0xD3,0x32,0x68,0xF2,0x4E,0xC2,0x60,0x74,0x3E,0xDC,0xE1,0xC6,0xC7,0xDD,0xEE,0x72,0x5A,0x93,0x6B,0xA8,0x14,0x91,0x5C,0x67,0x62,0xD2};
    Ip_u8 ciphertext_key256_keydata_192[] = {0xA8,0xF9,0xBC,0x16,0x12,0xC6,0x8B,0x3F,0xF6,0xE6,0xF4,0xFB,0xE3,0x0E,0x71,0xE4,0x76,0x9C,0x8B,0x80,0xA3,0x2C,0xB8,0x95,0x8C,0xD5,0xD1,0x7D,0x6B,0x25,0x4D,0xA1};
    Ip_u8 ciphertext_key256_keydata_256[] = {0x28,0xC9,0xF4,0x04,0xC4,0xB8,0x10,0xF4,0xCB,0xCC,0xB3,0x5C,0xFB,0x87,0xF8,0x26,0x3F,0x57,0x86,0xE2,0xD8,0x0E,0xD3,0x26,0xCB,0xC7,0xF0,0xE7,0x1A,0x99,0xF4,0x3B,0xFB,0x98,0x8B,0x9B,0x7A,0x02,0xDD,0x21};

#define AES_KEY_128 16
#define AES_KEY_192 24
#define AES_KEY_256 32

#define AES_KEK_128 16
#define AES_KEK_192 24
#define AES_KEK_256 32


    Ip_u8 output[128];
    Ip_u8 decryptedKey[128];
    Ip_u8 iv[AESKW_BLOCKSIZE];
    int outputLength,decryptedKeyLength;


    ipcom_printf("aeskeywrap test\n");

    /*   Test Vectors from RFC  */
    /*  128 Bit Key Encryption Key, 128 Bit Key */

    ipcom_memset(output,0,sizeof(output));
    outputLength = sizeof(output);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);
    aeskw_wrap(kek,AES_KEK_128,iv,sizeof(iv),keydata,AES_KEY_128,output,&outputLength);
    VALIDATE_TEST_RESULT(ciphertext_key128_keydata128,output,outputLength, "AES Keywrap: 128 KEK, 128 Key Encrypt");


    ipcom_memset(decryptedKey,0,sizeof(decryptedKey));
    decryptedKeyLength = sizeof(decryptedKey);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);

    aeskw_unwrap(kek, AES_KEK_128,iv,sizeof(iv),output,outputLength,decryptedKey,&decryptedKeyLength);

    VALIDATE_TEST_RESULT(keydata,decryptedKey,decryptedKeyLength,"AES Keywrap: 128 KEK, 128 Key Decrypt");

    /* 192 Bit Key Encryption Key, 128 Bit Key */

    ipcom_memset(output,0,sizeof(output));
    outputLength = sizeof(output);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);
    aeskw_wrap(kek,AES_KEK_192,iv,sizeof(iv),keydata,AES_KEY_128,output,&outputLength);
    VALIDATE_TEST_RESULT(ciphertext_key192_keydata128,output,outputLength, "AES Keywrap: 192 KEK, 128 Key Encrypt");


    ipcom_memset(decryptedKey,0,sizeof(decryptedKey));
    decryptedKeyLength = sizeof(decryptedKey);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);

    aeskw_unwrap(kek, AES_KEK_192,iv,sizeof(iv),output,outputLength,decryptedKey,&decryptedKeyLength);

    VALIDATE_TEST_RESULT(keydata,decryptedKey,decryptedKeyLength,"AES Keywrap: 192 KEK, 128 Key Decrypt");


    /* 256 Bit Key Encryption Key, 128 Bit Key */

    ipcom_memset(output,0,sizeof(output));
    outputLength = sizeof(output);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);
    aeskw_wrap(kek,AES_KEK_256,iv,sizeof(iv),keydata,AES_KEY_128,output,&outputLength);
    VALIDATE_TEST_RESULT(ciphertext_key256_keydata128,output,outputLength, "AES Keywrap: 256 KEK, 128 Key Encrypt");


    ipcom_memset(decryptedKey,0,sizeof(decryptedKey));
    decryptedKeyLength = sizeof(decryptedKey);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);

    aeskw_unwrap(kek, AES_KEK_256,iv,sizeof(iv),output,outputLength,decryptedKey,&decryptedKeyLength);

    VALIDATE_TEST_RESULT(keydata,decryptedKey,decryptedKeyLength,"AES Keywrap: 256 KEK, 128 Key Decrypt");



    /* 192 Bit Key Encryption Key, 192 Bit Key */

    ipcom_memset(output,0,sizeof(output));
    outputLength = sizeof(output);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);
    aeskw_wrap(kek,AES_KEK_192,iv,sizeof(iv),keydata,AES_KEY_192,output,&outputLength);
    VALIDATE_TEST_RESULT(ciphertext_key192_keydata_192,output,outputLength, "AES Keywrap: 192 KEK, 192 Key Encrypt");


    ipcom_memset(decryptedKey,0,sizeof(decryptedKey));
    decryptedKeyLength = sizeof(decryptedKey);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);

    aeskw_unwrap(kek, AES_KEK_192,iv,sizeof(iv),output,outputLength,decryptedKey,&decryptedKeyLength);

    VALIDATE_TEST_RESULT(keydata,decryptedKey,decryptedKeyLength,"AES Keywrap: 192 KEK, 192 Key Decrypt");

    /* 256 Bit Key Encryption Key, 192 Bit Key */

    ipcom_memset(output,0,sizeof(output));
    outputLength = sizeof(output);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);
    aeskw_wrap(kek,AES_KEK_256,iv,sizeof(iv),keydata,AES_KEY_192,output,&outputLength);
    VALIDATE_TEST_RESULT(ciphertext_key256_keydata_192,output,outputLength, "AES Keywrap: 256 KEK, 192 Key Encrypt");


    ipcom_memset(decryptedKey,0,sizeof(decryptedKey));
    decryptedKeyLength = sizeof(decryptedKey);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);

    aeskw_unwrap(kek, AES_KEK_256,iv,sizeof(iv),output,outputLength,decryptedKey,&decryptedKeyLength);

    VALIDATE_TEST_RESULT(keydata,decryptedKey,decryptedKeyLength,"AES Keywrap: 256 KEK, 192 Key Decrypt");


    /*256 Bit Key Encryption Key, 256 Bit Key */

    ipcom_memset(output,0,sizeof(output));
    outputLength = sizeof(output);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);
    aeskw_wrap(kek,AES_KEK_256,iv,sizeof(iv),keydata,AES_KEY_256,output,&outputLength);
    VALIDATE_TEST_RESULT(ciphertext_key256_keydata_256,output,outputLength, "AES Keywrap: 256 KEK, 256 KEK Encrypt");


    ipcom_memset(decryptedKey,0,sizeof(decryptedKey));
    decryptedKeyLength = sizeof(decryptedKey);
    ipcom_memcpy(iv,orig_iv,AESKW_BLOCKSIZE);

    aeskw_unwrap(kek, AES_KEK_256,iv,sizeof(iv),output,outputLength,decryptedKey,&decryptedKeyLength);

    VALIDATE_TEST_RESULT(keydata,decryptedKey,decryptedKeyLength,"AES Keywrap: 256 KEK, 256 KEK Decrypt");

    ipcom_printf("aeskeywraptest succeeds\n");

    return 1;

}


/*
 ****************************************************************************
 * 11                   PUBLIC FUNCTIONS
 ****************************************************************************
 */

/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */

