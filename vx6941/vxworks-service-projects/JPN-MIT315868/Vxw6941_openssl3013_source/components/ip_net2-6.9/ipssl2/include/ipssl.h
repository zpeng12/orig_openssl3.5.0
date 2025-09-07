/*
 ******************************************************************************
 *                     INTERPEAK API HEADER FILE
 *
 *   Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipssl.h,v $ $Revision: 1.9 $
 *   $Source: /home/interpeak/CVSRoot/ipssl2/include/ipssl.h,v $
 *   $Author: rboden $ $Date: 2010-09-16 08:15:50 $
 *   $State: Exp $ $Locker:  $
 *
 *   Copyright Interpeak AB 2000-2007 <www.interpeak.se>. All rights reserved.
 *     Design and implementation by Roger Boden <roger@interpeak.se>
 ******************************************************************************
 */
#ifndef IPSSL_H
#define IPSSL_H

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



/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */

#include <ipcom_type.h>
#include <ipcom_cstyle.h>

#include "ipssl_config.h"

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 ****************************************************************************
 * 4                    DEFINES
 ****************************************************************************
 */

#define IPSSL_RELEASE 60900

/*
 ****************************************************************************
 * 5                    TYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 6                    FUNCTIONS
 ****************************************************************************
 */

#ifdef IPSSL_USE_CMDS
#ifdef IPSSL_USE_CIPHERS_CMD
    IP_GLOBAL int ipssl_ciphers(int argc, char** argv);
#endif

#ifdef IPSSL_USE_S_CLIENT_CMD
    IP_GLOBAL int ipssl_s_client(int argc, char** argv);
#endif

#ifdef IPSSL_USE_S_SERVER_CMD
    IP_GLOBAL int ipssl_s_server(int argc, char** argv);
#endif

#ifdef IPSSL_USE_S_TIME_CMD
    IP_GLOBAL int ipssl_s_time(int argc, char** argv);
#endif

    IP_GLOBAL int ipssl_cmd_ssl_clt(int argc, char** argv);

    IP_GLOBAL int ipssl_cmd_ssl_srv(int argc, char** argv);
#endif /* IPSSL_USE_CMDS */

#if 0
#ifdef IPSSL_USE_TEST_CMDS
    IP_PUBLIC int ssltest_main(int argc, char** argv);
#endif
#endif

    IP_PUBLIC Ip_err ipssl_create(void);
    IP_PUBLIC Ip_err ipssl_start(void);

    void ipssl_tls1_PRF(const EVP_MD *md5, const EVP_MD *sha1,
                        unsigned char *label, int label_len,
                        const unsigned char *sec, int slen, unsigned char *out1,
                        unsigned char *out2, int olen);

#ifdef __cplusplus
}
#endif

#endif

/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */
