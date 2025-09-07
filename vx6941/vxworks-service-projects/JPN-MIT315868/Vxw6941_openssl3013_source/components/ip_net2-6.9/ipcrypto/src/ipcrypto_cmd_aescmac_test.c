/*
 ******************************************************************************
 *                     INTERPEAK SOURCE FILE
 *
 *   Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto_cmd_aescmac_test.c,v $ $Revision: 1.1 $
 *   $Source: /home/interpeak/CVSRoot/ipcrypto/src/ipcrypto_cmd_aescmac_test.c,v $
 *   $Author: roger $
 *   $State: Exp $ $Locker:  $
 *
 *   INTERPEAK_COPYRIGHT_STRING
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
                    ipcom_free(pCmacCtx); \
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
IP_GLOBAL int ipcrypto_cmd_aescmac_test(int argc, char **argv);

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
ipcrypto_cmd_aescmac_test(int argc, char **argv)
{
    /* messages common across the different key size tests (input message to be MAC'd), we just use subsets of message for 16 byte, 40 byte and 64 byte inputs */
    Ip_u8 message[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

    /* Using AES-128 as the Cipher */

    Ip_u8 key128[] ={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    Ip_u8 expectedK1_128[] = {0xfb,0xee,0xd6,0x18,0x35,0x71,0x33,0x66,0x7c,0x85,0xe0,0x8f,0x72,0x36,0xa8,0xde};
    Ip_u8 expectedK2_128[] = {0xf7,0xdd,0xac,0x30,0x6a,0xe2,0x66,0xcc,0xf9,0x0b,0xc1,0x1e,0xe4,0x6d,0x51,0x3b};
    Ip_u8 expectedOutputMessage0_128[] = {0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46};
    Ip_u8 expectedOutputMessage16_128[] = {0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c};
    Ip_u8 expectedOutputMessage40_128[] = {0xdf,0xa6,0x67,0x47,0xde,0x9a,0xe6,0x30,0x30,0xca,0x32,0x61,0x14,0x97,0xc8,0x27};
    Ip_u8 expectedOutputMessage64_128[] = {0x51,0xf0,0xbe,0xbf,0x7e,0x3b,0x9d,0x92,0xfc,0x49,0x74,0x17,0x79,0x36,0x3c,0xfe};

    /* Using AES-192 as the Cipher */
    Ip_u8 key192[] ={ 0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};
    Ip_u8 expectedK1_192[] = {0x44,0x8a,0x5b,0x1c,0x93,0x51,0x4b,0x27,0x3e,0xe6,0x43,0x9d,0xd4,0xda,0xa2,0x96};
    Ip_u8 expectedK2_192[] = {0x89,0x14,0xb6,0x39,0x26,0xa2,0x96,0x4e,0x7d,0xcc,0x87,0x3b,0xa9,0xb5,0x45,0x2c};
    Ip_u8 expectedOutputMessage0_192[] = {0xd1,0x7d,0xdf,0x46,0xad,0xaa,0xcd,0xe5,0x31,0xca,0xc4,0x83,0xde,0x7a,0x93,0x67};
    Ip_u8 expectedOutputMessage16_192[] = {0x9e,0x99,0xa7,0xbf,0x31,0xe7,0x10,0x90,0x06,0x62,0xf6,0x5e,0x61,0x7c,0x51,0x84};
    Ip_u8 expectedOutputMessage40_192[] = {0x8a,0x1d,0xe5,0xbe,0x2e,0xb3,0x1a,0xad,0x08,0x9a,0x82,0xe6,0xee,0x90,0x8b,0x0e};
    Ip_u8 expectedOutputMessage64_192[] = {0xa1,0xd5,0xdf,0x0e,0xed,0x79,0x0f,0x79,0x4d,0x77,0x58,0x96,0x59,0xf3,0x9a,0x11};

    /* Using AES-256 as the Cipher */

    Ip_u8 key256[] ={ 0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    Ip_u8 expectedK1_256[] = {0xca,0xd1,0xed,0x03,0x29,0x9e,0xed,0xac,0x2e,0x9a,0x99,0x80,0x86,0x21,0x50,0x2f};
    Ip_u8 expectedK2_256[] = {0x95,0xa3,0xda,0x06,0x53,0x3d,0xdb,0x58,0x5d,0x35,0x33,0x01,0x0c,0x42,0xa0,0xd9};
    Ip_u8 expectedOutputMessage0_256[] = {0x02,0x89,0x62,0xf6,0x1b,0x7b,0xf8,0x9e,0xfc,0x6b,0x55,0x1f,0x46,0x67,0xd9,0x83};
    Ip_u8 expectedOutputMessage16_256[] = {0x28,0xa7,0x02,0x3f,0x45,0x2e,0x8f,0x82,0xbd,0x4b,0xf2,0x8d,0x8c,0x37,0xc3,0x5c};
    Ip_u8 expectedOutputMessage40_256[] = {0xaa,0xf3,0xd8,0xf1,0xde,0x56,0x40,0xc2,0x32,0xf5,0xb1,0x69,0xb9,0xc9,0x11,0xe6};
    Ip_u8 expectedOutputMessage64_256[] = {0xe1,0x99,0x21,0x90,0x54,0x9f,0x6e,0xd5,0x69,0x6a,0x2c,0x05,0x6c,0x31,0x54,0x10};

    /* AES-CMAC-PRF128 Test vectors */

    Ip_u8 keyPRF128[] ={ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xed,0xcb};
    Ip_u8 messagePRF128[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13};
    Ip_u8 expectedOutputPRF128_18[] = {0x84,0xa3,0x48,0xa4,0xa4,0x5d,0x23,0x5b,0xab,0xff,0xfc,0x0d,0x2b,0x4d,0xa0,0x9a};
    Ip_u8 expectedOutputPRF128_16[] = {0x98,0x0a,0xe8,0x7b,0x5f,0x4c,0x9c,0x52,0x14,0xf5,0xb6,0xa8,0x45,0x5e,0x4c,0x2d};
    Ip_u8 expectedOutputPRF128_10[] = {0x29,0x0d,0x9e,0x11,0x2e,0xdb,0x09,0xee,0x14,0x1f,0xcf,0x64,0xc0,0xb7,0x2f,0x3d};

    /* begin Tests */

    Ip_u8 output[AES_BLOCKSIZE];
    Ip_u8 *input =IP_NULL;
    int outputLength;
    AES_CMAC_CTX *pCmacCtx;

    pCmacCtx = ipcom_malloc(sizeof(AES_CMAC_CTX));
    if(!pCmacCtx)
    {
        ipcom_printf("Failed. Out of memory");
        return -1;
    }

    /* TEST1:  passing IP_NULL Ctx and IP_NULL key, should fail */
    if (-1 != aesCmacInit(IP_NULL,IP_NULL,0))
    {
        ipcom_printf("aesCmacInit Failed IP_NULL, IP_NULL test\n");
        ipcom_free(pCmacCtx);
        return -1;
    }

    ipcom_memset(pCmacCtx,0,sizeof(AES_CMAC_CTX));
    /* AES-128 Reusing CTX, and checking sub keys generated and stored in CTX from a known key */
    aesCmacInit(pCmacCtx,key128,sizeof(key128));

    VALIDATE_TEST_RESULT(expectedK1_128,pCmacCtx->k1,AES_BLOCKSIZE,"AES128 Gen Sub Key1");
    VALIDATE_TEST_RESULT(expectedK2_128,pCmacCtx->k2,AES_BLOCKSIZE,"AES128 Gen Sub Key2");



    /* Test: passing too small of output buffer */

    outputLength = 2;
    if (-1 != aesCmacFinal(pCmacCtx, input,0,output,&outputLength))
    {
        ipcom_printf("invalid outputLength test fails\n");
        ipcom_free(pCmacCtx);
        return -1;
    }
    else
    {
        ipcom_printf("Invalid outputLength test pass\n");
    }

    /* AES-128 empty string for input*/
    outputLength = sizeof(output);
    aesCmacFinal(pCmacCtx, input,0,output,&outputLength);

    VALIDATE_TEST_RESULT(expectedOutputMessage0_128,output,sizeof(expectedOutputMessage0_128),"AES128 0 Byte Message");

    ipcom_memset(output,0,AES_BLOCKSIZE);
    /* AES-128, reusing CTX  (since key, subkeys did not change) , empty string block mode*/
    aesCmacBlock(pCmacCtx,key128,sizeof(key128),input,0,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage0_128,output,sizeof(expectedOutputMessage0_128),"AES128 0 Byte Message Blockmode, Context reuse");


    /* AES-128, reusing CTX  (since key, subkeys did not change) ,  16 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key128,sizeof(key128),message,16,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage16_128,output,sizeof(expectedOutputMessage16_128),"AES128 16 Byte Message aesCmacBlock");

    /* AES-128, reusing CTX  (since key, subkeys did not change) ,  40 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key128,sizeof(key128),message,40,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage40_128,output,sizeof(expectedOutputMessage40_128),"AES128 40 Byte Message aesCmacBlock");

    /* AES-128, reusing CTX  (since key, subkeys did not change) ,  64 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key128,sizeof(key128),message,64,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage64_128,output,sizeof(expectedOutputMessage64_128),"AES128 64 Byte Message aesCmacBlock");

    /***********************************************************************************************
    AES-192 CMAC tests
    ***********************************************************************************************/

    ipcom_memset(pCmacCtx,0,sizeof(AES_CMAC_CTX));
    /*AES-192 Reusing CTX, and checking sub keys generated and stored in CTX from a known key */
    aesCmacInit(pCmacCtx,key192,sizeof(key192));

    VALIDATE_TEST_RESULT(expectedK1_192,pCmacCtx->k1,AES_BLOCKSIZE,"AES192 Gen Sub Key1");
    VALIDATE_TEST_RESULT(expectedK2_192,pCmacCtx->k2,AES_BLOCKSIZE,"AES192 Gen Sub Key2");

    /*  AES-192 empty string for input*/
    outputLength = sizeof(output);
    aesCmacFinal(pCmacCtx, input,0,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage0_192,output,sizeof(expectedOutputMessage0_192),"AES192 0 Byte Message");

    ipcom_memset(output,0,AES_BLOCKSIZE);
    /* AES-192, reusing CTX  (since key, subkeys did not change) , empty string block mode*/
    aesCmacBlock(pCmacCtx,key192,sizeof(key192),input,0,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage0_192,output,sizeof(expectedOutputMessage0_192),"AES192 0 Byte Message Blockmode, Context reuse");


    /* AES-192, reusing CTX  (since key, subkeys did not change) ,  16 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key192,sizeof(key192),message,16,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage16_192,output,sizeof(expectedOutputMessage16_192),"AES192 16 Byte Message aesCmacBlock");

    /* AES-192, reusing CTX  (since key, subkeys did not change) ,  40 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key192,sizeof(key192),message,40,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage40_192,output,sizeof(expectedOutputMessage40_192),"AES192 40 Byte Message aesCmacBlock");

    /* AES-192, reusing CTX  (since key, subkeys did not change) ,  64 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key192,sizeof(key192),message,64,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage64_192,output,sizeof(expectedOutputMessage64_192),"AES192 64 Byte Message aesCmacBlock");

    /***********************************************************************************************
                AES-256 CMAC tests
            ***********************************************************************************************/

    ipcom_memset(pCmacCtx,0,sizeof(AES_CMAC_CTX));
    /*AES-256 Reusing CTX, and checking sub keys generated and stored in CTX from a known key */
    aesCmacInit(pCmacCtx,key256,sizeof(key256));

    VALIDATE_TEST_RESULT(expectedK1_256,pCmacCtx->k1,AES_BLOCKSIZE,"AES256 Gen Sub Key1");
    VALIDATE_TEST_RESULT(expectedK2_256,pCmacCtx->k2,AES_BLOCKSIZE,"AES256 Gen Sub Key2");

    /*  AES-256 empty string for input*/
    outputLength = sizeof(output);
    aesCmacFinal(pCmacCtx, input,0,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage0_256,output,sizeof(expectedOutputMessage0_256),"AES256 0 Byte Message");

    ipcom_memset(output,0,AES_BLOCKSIZE);
    /* AES-256, reusing CTX from Test3 (since key, subkeys did not change) , empty string block mode*/
    aesCmacBlock(pCmacCtx,key256,sizeof(key256),input,0,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage0_256,output,sizeof(expectedOutputMessage0_256),"AES256 0 Byte Message Blockmode, Context reuse");


    /* AES-256, reusing CTX  (since key, subkeys did not change) ,  16 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key256,sizeof(key256),message,16,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage16_256,output,sizeof(expectedOutputMessage16_256),"AES256 16 Byte Message aesCmacBlock");

    /* AES-256, reusing CTX  (since key, subkeys did not change) ,  40 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key256,sizeof(key256),message,40,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage40_256,output,sizeof(expectedOutputMessage40_256),"AES256 40 Byte Message aesCmacBlock");

    /* AES-256, reusing CTX  (since key, subkeys did not change) ,  64 byte input message*/
    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacBlock(pCmacCtx,key256,sizeof(key256),message,64,output,&outputLength);
    VALIDATE_TEST_RESULT(expectedOutputMessage64_256,output,sizeof(expectedOutputMessage64_256),"AES256 64 Byte Message aesCmacBlock");


    /***********************************************************************************************
    		AES-CMAC-PRF-128 CMAC tests
    ***********************************************************************************************/

    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacPrf128(keyPRF128, 18, messagePRF128, sizeof(messagePRF128), output, &outputLength);
    VALIDATE_TEST_RESULT(expectedOutputPRF128_18,output,sizeof(expectedOutputPRF128_18),"AES-CMAC-PRF-128 18 byte key");

    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacPrf128(keyPRF128, 16, messagePRF128, sizeof(messagePRF128), output, &outputLength);
    VALIDATE_TEST_RESULT(expectedOutputPRF128_16,output,sizeof(expectedOutputPRF128_16),"AES-CMAC-PRF-128 16 byte key");

    ipcom_memset(output,0,AES_BLOCKSIZE);
    aesCmacPrf128(keyPRF128, 10, messagePRF128, sizeof(messagePRF128), output, &outputLength);
    VALIDATE_TEST_RESULT(expectedOutputPRF128_10,output,sizeof(expectedOutputPRF128_10),"AES-CMAC-PRF-128 10 byte key");


    ipcom_printf("cmactest succeeds\n");

    ipcom_free(pCmacCtx);

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

