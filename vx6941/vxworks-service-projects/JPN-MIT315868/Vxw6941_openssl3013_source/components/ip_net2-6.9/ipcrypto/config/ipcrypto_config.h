/*
 ******************************************************************************
 *                     INTERPEAK CONFIGURATION HEADER FILE
 *
 *   Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto_config.h,v $ $Revision: 1.37.10.1 $
 *   $Source: /home/interpeak/CVSRoot/ipcrypto/config/ipcrypto_config.h,v $
 *   $Author: svc-cmnet $ $Date: 2013-03-13 07:45:18 $
 *   $State: Exp $ $Locker:  $
 *
 *   Copyright Interpeak AB 2000-2003 <www.interpeak.se>. All rights reserved.
 *     Design and implementation by Roger Boden <roger@interpeak.se>
 ******************************************************************************
 */
#ifndef IPCRYPTO_CONFIG_H
#define IPCRYPTO_CONFIG_H

/*
 ****************************************************************************
 * 1                    DESCRIPTION
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 2                    INCLUDE FILES
 ****************************************************************************
 */


#ifdef __cplusplus
extern "C" {
#endif

/*
 ****************************************************************************
 * 3                    DEFINES
 ****************************************************************************
 */

/*
 *===========================================================================
 *                         IPCRYPTO_SYSLOG_PRIORITY
 *===========================================================================
 * Default syslog priority.
 */
#ifdef IP_DEBUG
#define IPCRYPTO_SYSLOG_PRIORITY  IPCOM_LOG_DEBUG /* (see ipcom_syslog.h) */
#else
#define IPCRYPTO_SYSLOG_PRIORITY  IPCOM_LOG_WARNING
#endif


#ifdef IP_SIZE
#define IPCRYPTO_MINIMUM_FOOTPRINT
#endif

#ifdef IPCRYPTO_MINIMUM_FOOTPRINT

    /* Hash algorithms */
#define OPENSSL_NO_MD2
#define OPENSSL_NO_MD4
#define OPENSSL_NO_RIPEMD
#define OPENSSL_NO_RIPEMD160
#define OPENSSL_NO_RMD160

    /* Symmetrical algorithms */
    /*#define OPENSSL_NO_AES*/
#define OPENSSL_NO_BF
#define OPENSSL_NO_CAST
#define OPENSSL_NO_CHAIN_VERIFY
#define OPENSSL_NO_DESCBCM
#define OPENSSL_NO_RC4
#define OPENSSL_NO_RC2

    /* Asymmetrical algorithms */
/* These algorithms are needed by IPIKE, IPSSH, IPSSL, IPWEBS */
/* #define OPENSSL_NO_DH */
/* #define OPENSSL_NO_DSA */
/* ipwebs and ipsslproxy require RSA */
/* #define OPENSSL_NO_RSA */


#define OPENSSL_NO_KRB5
/* #define OPENSSL_NO_OCSP */

#endif

#define DSO_NONE

    /* The following algorithms have an unclear patent situation, hence we exclude them */
#define OPENSSL_NO_MDC2
/*#define OPENSSL_NO_EC
#define OPENSSL_NO_ECDH
#define OPENSSL_NO_ECDSA*/
#define OPENSSL_NO_IDEA
/*#define OPENSSL_NO_SM2*/

    /* The following test do not have test case in 3.x, hence we exclude them */
#define OPENSSL_NO_RIPEMD_TEST
#define OPENSSL_NO_JPAKE_TEST
#define OPENSSL_NO_MD2_TEST
#define OPENSSL_NO_MD4_TEST
#define OPENSSL_NO_MD5_TEST

#ifdef OPENSSL_FIPS
#define OPENSSL_NO_MD2
/*#define OPENSSL_NO_MD4*/
#define OPENSSL_NO_RIPEMD
#define OPENSSL_NO_RIPEMD160
#define OPENSSL_NO_RMD160

#define OPENSSL_NO_BF
#define OPENSSL_NO_CAST
#define OPENSSL_NO_RC4
#define OPENSSL_NO_RC2
#endif

/*
 *===========================================================================
 *                         OPENSSL_NO_S
 *===========================================================================
 */
#ifdef IPSSL
#include <ipssl_config.h>
#else
#define OPENSSL_NO_SSL2
#define OPENSSL_NO_SSL3
#define OPENSSL_NO_TLS
#define OPENSSL_NO_TLS1
#endif


/*
 *===========================================================================
 *                         IPCRYPTO_DEFAULT_CONFIG_FILE
 *===========================================================================
 */
#define IPCRYPTO_DEFAULT_CONFIG_FILE "/ram/openssl.cnf"


/*
 *===========================================================================
 *                         IPCRYPTO_USE_APPS
 *===========================================================================
 * Define to include openssl shell command applications.
 */
#if !defined(IP_PORT_ITRON) && !defined(IP_PORT_WIN32) && !defined(IPCRYPTO_MINIMUM_FOOTPRINT)
#define IPCRYPTO_USE_APPS
#endif


/*
 *===========================================================================
 *                         IPCRYPTO_USE_TEST
 *===========================================================================
 * Define to include openssl shell command test tools.
#if !defined(IP_PORT_ITRON) && !defined(IPCRYPTO_MINIMUM_FOOTPRINT)
#endif
 */
#define IPCRYPTO_USE_TEST


/*
 *===========================================================================
 *                         IPCRYPTO_USE_KEY_DB_EXAMPLE_KEYS
 *===========================================================================
 * Define to install example DSA and RSA keys in the key db.
 */
#ifdef IPCOM_USE_KEY_DB
#define IPCRYPTO_USE_KEY_DB_EXAMPLE_KEYS
#endif

/*
 ****************************************************************************
 * 4                    TYPES
 ****************************************************************************
 */

/*
 ****************************************************************************
 * 5                    FUNCTIONS
 ****************************************************************************
 */


#ifdef __cplusplus
}
#endif

#endif


/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */
