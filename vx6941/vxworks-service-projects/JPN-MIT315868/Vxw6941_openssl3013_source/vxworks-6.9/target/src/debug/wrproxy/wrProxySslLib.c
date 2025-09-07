/* wrProxySslLib.c - Secure Sockets Layer support for WR proxy */

/*
 * Copyright (c) 2011,2013 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
modification history
--------------------
01l,18oct13,elp  checked return value of clock_gettime().
01k,27aug13,elp  checked SSL_CTX_LOAD_VERIFY_LOC and SSL_SET_FD return value
01j,31may11,rlp  Did not hardcode dll extension on UNIX (CQ:WIND00279136).
           +fle  Fix for defect CQ:WIND00279400 - target server crash on Windows
01i,12may11,rlp  Used IPCOM secure key database to store the private key
                 (WIND00271834).
01h,02may11,fle  Defect CQ:WIND00270014 - fixed dll name on Windows
01g,12apr11,rlp  Fixed library path for Unix (WIND00266959).
01f,11apr11,rlp  Fixed windows execution.
01e,04apr11,rlp  Windows host build.
01d,01apr11,rlp  Worked around netDrv issues.
01c,01apr11,rlp  Fixed dependencies on SSL library.
01b,31mar11,rlp  Added support for the host side.
01a,22mar11,rlp  written
*/

/*
DESCRIPTION
This library provides the Secure Sockets Layer (SSL) support for the WR proxy.
Connections established with this library understand the SSLv2, SSLv3, and
TLSv1 protocol.

This library is able to create SSL proxy server and SSL proxy client. Both SSL
proxy server and proxy client are created with the SSL_VERIFY_PEER attribute.
It means that:

- Proxy server sends a client certificate request to the client. The
certificate returned (if any) is checked. If the verification process fails,
the TLS/SSL handshake is immediately terminated with an alert message
containing the reason for the verification failure.

- Proxy client verifies the server certificate. If the verification process
fails, the TLS/SSL handshake is immediately terminated with an alert message
containing the reason for the verification failure.

CONFIGURATION
In order to include the SSL support to the WR proxy, the VSB must define the
IPNET SSL support (i.e include the COMPONENT_IPSSL option). Once the VSB has
been built, configure the VxWorks image project with the INCLUDE_WDB_PROXY_SSL
component to get the secured WR proxy.

INCLUDE FILES: wrProxyLib.h
*/

/* Includes */

#ifndef HOST
#   include <vxWorks.h>
#   include <selectLib.h>
#   include <errnoLib.h>
#   include <wrn/coreip/hostLib.h>
#   include <wrn/coreip/wrapper/wrapperHostLib.h>
#   include <dirent.h>
#   include <ipcom_key_db.h>
#   include <ipcom_err.h>
#else	/* HOST */
#   include <host.h>
#   include <time.h>
#   include <dynlklib.h>
#   include <wpwrutil.h>

#   ifndef WIN32
#	include <dirent.h>
#	include <sys/select.h>
#   else
#	include <win32/direntw.h>
#   endif	/* !WIN32 */

#endif  /* HOST */

#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <ctype.h>
#include <openssl/types.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "wrProxyLib.h"
#include "wrProxyLibP.h"

/* Defines */

#if	defined(HOST) && defined(LINUX)
#define CLOCK_REALTIME 1
#endif  /* defined(HOST) && defined(LINUX) */

#define	PROXY_RSA_NUM_BITS	2048	/* Default RSA private key length */
#define	PROXY_RSA_EXP		3	/* RSA public exponent */

#ifdef HOST

#ifdef WIN32
#define	SSL_DLL_NAME		"ssleay32"
#define	CRYPTO_DLL_NAME		"libeay32"
#else
#define	SSL_DLL_NAME		"libssl"
#define	CRYPTO_DLL_NAME		"libcrypto"
#endif /* WIN32 */

#define	PRINT_ERR(x,y)		wpwrLogMsg(x, y)

#define	PROXY_SSL_RTN_NUM	20	/* num of SSL shared library APIs */
#define	PROXY_CRYPTO_RTN_NUM	8	/* num of Crypto shared library APIs */

#define	SSL_LOAD_ERROR_STRINGS_RTN	(void) sslLibRtn[0].func
#define	SSL_LIBRARY_INIT		(void) sslLibRtn[1].func
#define	SSL_CTX_NEW			(SSL_CTX *) sslLibRtn[2].func
#define	SSL_CTX_FREE			(void) sslLibRtn[3].func
#define	SSL_NEW				(SSL *) sslLibRtn[4].func
#define	SSL_FREE			(void) sslLibRtn[5].func
#define	SSL_SHUTDOWN			sslLibRtn[6].func
#define	SSL_WRITE			sslLibRtn[7].func
#define	SSL_READ			sslLibRtn[8].func
#define	SSL_SET_ACCEPT_STATE		(void) sslLibRtn[9].func
#define	SSL_SET_CONNECT_STATE		(void) sslLibRtn[10].func
#define	SSL_GET_ERROR			sslLibRtn[11].func
#define	SSL_GET_SSL_CTX			(SSL_CTX *) sslLibRtn[12].func
#define	SSL_GET_FD			sslLibRtn[13].func
#define	SSL_SET_FD			sslLibRtn[14].func
#define	SSL_CTX_SET_VERIFY		(void) sslLibRtn[15].func
#define	SSLV23_METHOD			sslLibRtn[16].func
#define	SSL_USE_CERTIFICATE		sslLibRtn[17].func
#define	SSL_USE_PRIVATEKEY		sslLibRtn[18].func
#define	SSL_CTX_LOAD_VERIFY_LOC		(void) sslLibRtn[19].func

#define	RAND_STATUS			cryptoLibRtn[0].func
#define RAND_ADD			(void) cryptoLibRtn[1].func
#define	PEM_READ_RSAPRIVATEKEY		(RSA *) cryptoLibRtn[2].func
#define	PEM_READ_X509			(X509 *) cryptoLibRtn[3].func
#define	ERR_GET_ERROR			cryptoLibRtn[4].func
#define	ERR_ERROR_STRING		(char *) cryptoLibRtn[5].func
#define	X509_CMP			cryptoLibRtn[6].func
#define	X509_STORE_CTX_GET_CURRENT_CERT	cryptoLibRtn[7].func
#else	/* HOST */

#define	PRINT_ERR(x,y)			fprintf(stderr, x, y)

#define	SSL_LOAD_ERROR_STRINGS_RTN	SSL_load_error_strings
#define	SSL_LIBRARY_INIT		SSL_library_init
#define	SSL_CTX_NEW			SSL_CTX_new
#define	SSL_CTX_FREE			SSL_CTX_free
#define	SSL_NEW				SSL_new
#define	SSL_FREE			SSL_free
#define	SSL_SHUTDOWN			SSL_shutdown
#define	SSL_WRITE			SSL_write
#define	SSL_READ			SSL_read
#define	SSL_SET_ACCEPT_STATE		SSL_set_accept_state
#define	SSL_SET_CONNECT_STATE		SSL_set_connect_state
#define	SSL_GET_ERROR			SSL_get_error
#define	SSL_GET_SSL_CTX			SSL_get_SSL_CTX
#define	SSL_GET_FD			SSL_get_fd
#define	SSL_SET_FD			SSL_set_fd
#define	SSL_CTX_SET_VERIFY		SSL_CTX_set_verify
#define	SSLV23_METHOD			SSLv23_method
#define	SSL_USE_CERTIFICATE		SSL_use_certificate
#define	SSL_USE_PRIVATEKEY		SSL_use_PrivateKey
#define	SSL_CTX_LOAD_VERIFY_LOC		SSL_CTX_load_verify_locations

#define	RAND_STATUS			RAND_status
#define RAND_ADD			RAND_add
#define	PEM_READ_RSAPRIVATEKEY		PEM_read_RSAPrivateKey
#define	PEM_READ_X509			PEM_read_X509
#define	ERR_GET_ERROR			ERR_get_error
#define	ERR_ERROR_STRING		ERR_error_string
#define	X509_CMP			X509_cmp
#define	X509_STORE_CTX_GET_CURRENT_CERT	X509_STORE_CTX_get_current_cert
#endif	/* HOST */

/* Globals */

int wrProxySslLibDebug = 0;

/* Locals */

#ifdef HOST
LOCAL DYNLK_FUNC sslLibRtn [PROXY_SSL_RTN_NUM]; 
LOCAL DYNLK_FUNC cryptoLibRtn [PROXY_CRYPTO_RTN_NUM]; 
#else	/* HOST */
LOCAL const char * issuerName = "WindRiver WDB Agent Proxy";
LOCAL const char * subjectName = "WindRiver WDB Agent Proxy";
#endif	/* HOST */

LOCAL const char * fileName = "wrdebug";
LOCAL const char * certRepository = NULL;	/* Path to the private key */
						/* and certificate repository */

/* Forward declarations */

LOCAL ssize_t	wrProxySslRW (void * pCookie, char * buffer,
					size_t size, BOOL write);

#ifdef	HOST
#   ifndef WIN32
LOCAL BOOL	wrProxySslDllFind (char * dir, char * dllName,
				   char * dllResName);

/*******************************************************************************
*
* wrProxySslDllFind - Look for a dll
*
* This routine looks for a dll starting with the <dllName> string into the
* <dirPath> directory. If such dll exists, it copies the full name to the
* memory area pointed by <dllResName>.
*
* RETURNS: TRUE if a dll has been found, otherwise FALSE.
*
* ERRNO: N/A
*
* NOMANUAL
*/

LOCAL BOOL wrProxySslDllFind
    (
    char *	dirPath,
    char *	dllName,
    char *	dllResName
    )
    {
    DIR *	dir;
    BOOL	ret = FALSE;

    if (dirPath == NULL)
    	return ret;

    if ((dir = opendir (dirPath)) == NULL)
	{
    	PRINT_ERR ("Can't open %s directory\n", dirPath);
	return ret;
	}

    while (TRUE)
	{
	struct dirent *	pEntry;

	if ((pEntry = readdir (dir)) == NULL)
	    break;

	if (strncmp (pEntry->d_name, dllName, strlen (dllName)) == 0)
	    {
	    sprintf (dllResName, "%s/%s", dirPath, pEntry->d_name);
	    ret = TRUE;
	    break;
	    }
	}

    closedir (dir);
    return ret;
    }
#   endif /* WIN32 */
#endif /* HOST */

/*******************************************************************************
*
* wrProxySslLibInit - Initialize the SSL support for the WR proxy library
*
* This routine initializes the SSL support for the WR proxy. It performs
* various OpenSSL initializations and sets the path to the private key and
* certificate required by the authentication.
*
* RETURNS: Always OK
*
* ERRNO: N/A
*
* NOMANUAL
*/

STATUS wrProxySslLibInit
    (
    char * certDir	/* path to the private key and certificate repository */
    )
    {
    LOCAL BOOL		wrProxySslLibInitialized	= FALSE;
#ifdef	HOST
#   ifndef WIN32
    struct timespec	ts;
    void *		sslHandle		= NULL;
    void *		cryptoHandle		= NULL;
    char *		extension		= "so";
    char		dllName [MAXPATHLEN]	= {0};
    int			sslNumElems		= 0;
    int			cryptoNumElems		= 0;
    char *		windLibName		= NULL;
    char *		dllDir[]		= {"/lib", "/usr/lib", NULL};
    BOOL		dllFound		= FALSE;
#   else
    LARGE_INTEGER	counter;
#   endif /* ! WIN32 */
    int			ix			= 0;	/* sym iter */
#else	/* HOST */
    struct timespec	ts;
#endif	/* HOST */

    if (wrProxySslLibInitialized)
    	return OK;

#ifdef	HOST
    sslLibRtn[0].name = "SSL_load_error_strings"; 
    sslLibRtn[1].name = "SSL_library_init"; 
    sslLibRtn[2].name = "SSL_CTX_new"; 
    sslLibRtn[3].name = "SSL_CTX_free"; 
    sslLibRtn[4].name = "SSL_new"; 
    sslLibRtn[5].name = "SSL_free"; 
    sslLibRtn[6].name = "SSL_shutdown"; 
    sslLibRtn[7].name = "SSL_write"; 
    sslLibRtn[8].name = "SSL_read"; 
    sslLibRtn[9].name = "SSL_set_accept_state"; 
    sslLibRtn[10].name = "SSL_set_connect_state"; 
    sslLibRtn[11].name = "SSL_get_error"; 
    sslLibRtn[12].name = "SSL_get_SSL_CTX"; 
    sslLibRtn[13].name = "SSL_get_fd"; 
    sslLibRtn[14].name = "SSL_set_fd"; 
    sslLibRtn[15].name = "SSL_CTX_set_verify"; 
    sslLibRtn[16].name = "SSLv23_method"; 
    sslLibRtn[17].name = "SSL_use_certificate"; 
    sslLibRtn[18].name = "SSL_use_RSAPrivateKey"; 
    sslLibRtn[19].name = "SSL_CTX_load_verify_locations"; 

    cryptoLibRtn[0].name = "RAND_status"; 
    cryptoLibRtn[1].name = "RAND_add"; 
    cryptoLibRtn[2].name = "PEM_read_RSAPrivateKey"; 
    cryptoLibRtn[3].name = "PEM_read_X509"; 
    cryptoLibRtn[4].name = "ERR_get_error"; 
    cryptoLibRtn[5].name = "ERR_error_string"; 
    cryptoLibRtn[6].name = "X509_cmp"; 
    cryptoLibRtn[7].name = "X509_STORE_CTX_get_current_cert"; 

#ifdef WIN32
    /*
     * On Windows, the ssl lib is linked statically. We have to initialise the
     * the various function pointer using the Windows APIs.
     */

    sslLibRtn[0].func = (int (*)()) SSL_load_error_strings; 
    sslLibRtn[1].func = (int (*)()) SSL_library_init; 
    sslLibRtn[2].func = (int (*)()) SSL_CTX_new; 
    sslLibRtn[3].func = (int (*)()) SSL_CTX_free; 
    sslLibRtn[4].func = (int (*)()) SSL_new; 
    sslLibRtn[5].func = (int (*)()) SSL_free; 
    sslLibRtn[6].func = (int (*)()) SSL_shutdown;
    sslLibRtn[7].func = (int (*)()) SSL_write;
    sslLibRtn[8].func = (int (*)()) SSL_read; 
    sslLibRtn[9].func = (int (*)()) SSL_set_accept_state; 
    sslLibRtn[10].func = (int (*)()) SSL_set_connect_state; 
    sslLibRtn[11].func = (int (*)()) SSL_get_error; 
    sslLibRtn[12].func = (int (*)()) SSL_get_SSL_CTX; 
    sslLibRtn[13].func = (int (*)()) SSL_get_fd; 
    sslLibRtn[14].func = (int (*)()) SSL_set_fd; 
    sslLibRtn[15].func = (int (*)()) SSL_CTX_set_verify; 
    sslLibRtn[16].func = (int (*)()) SSLv23_method; 
    sslLibRtn[17].func = (int (*)()) SSL_use_certificate; 
    sslLibRtn[18].func = (int (*)()) SSL_use_RSAPrivateKey; 
    sslLibRtn[19].func = (int (*)()) SSL_CTX_load_verify_locations; 

    cryptoLibRtn[0].func = (int (*)()) RAND_status; 
    cryptoLibRtn[1].func = (int (*)()) RAND_add; 
    cryptoLibRtn[2].func = (int (*)()) PEM_read_RSAPrivateKey; 
    cryptoLibRtn[3].func = (int (*)()) PEM_read_X509; 
    cryptoLibRtn[4].func = (int (*)()) ERR_get_error; 
    cryptoLibRtn[5].func = (int (*)()) ERR_error_string; 
    cryptoLibRtn[6].func = (int (*)()) X509_cmp; 
    cryptoLibRtn[7].func = (int (*)()) X509_STORE_CTX_get_current_cert; 
#else
    /*
     * Look for the libssl.so library in the LD_LIBRARY_PATH if the
     * WIND_FOUNDATION_SSL_LIB_NAME environment variable is not defined.
     */

    if ((windLibName = getenv ("WIND_FOUNDATION_SSL_LIB_NAME")) != NULL)
	snprintf (dllName, MAXPATHLEN, "%s", windLibName);
    else
	sprintf (dllName, "%s.%s", SSL_DLL_NAME, extension);

dynlkSslAgain:
    sslNumElems = dynlkAbsPathFvBind (dllName, sslLibRtn, NELEMENTS (sslLibRtn),
				      &sslHandle);

    if (sslNumElems != NELEMENTS(sslLibRtn))
	{
	if ((windLibName == NULL) &&
	    ((wrProxySslDllFind (dllDir[ix++], dllName, dllName)) ||
	     (dllDir[ix] != NULL)))
	    goto dynlkSslAgain;
	}
    else
	dllFound = TRUE;

    if (!dllFound)
	{
	PRINT_ERR ("Can't open %s shared library\n", dllName);
	return ERROR;
	}

    /*
     * Look for the libcrypto.so library in the LD_LIBRARY_PATH if the
     * WIND_FOUNDATION_CRYPTO_LIB_NAME environment variable is not defined.
     */

    if ((windLibName = getenv ("WIND_FOUNDATION_CRYPTO_LIB_NAME")) != NULL)
	snprintf (dllName, MAXPATHLEN, "%s", windLibName);
    else
	sprintf (dllName, "%s.%s", CRYPTO_DLL_NAME, extension);

    ix		= 0;
    dllFound	= FALSE;

dynlkCryptoAgain:
    cryptoNumElems = dynlkAbsPathFvBind (dllName, cryptoLibRtn,
					 NELEMENTS (cryptoLibRtn),
					 &cryptoHandle);

    if (cryptoNumElems != NELEMENTS (cryptoLibRtn))
	{
	if ((windLibName == NULL) &&
	    ((wrProxySslDllFind (dllDir[ix++], dllName, dllName)) ||
	     (dllDir[ix] != NULL)))
	    goto dynlkCryptoAgain;
	}
    else
	dllFound = TRUE;

    if (!dllFound)
	{
	PRINT_ERR ("Can't open %s shared library\n", dllName);
	return ERROR;
	}
#endif /* WIN32 */
#endif	/* HOST */

    certRepository = certDir;

    SSL_LOAD_ERROR_STRINGS_RTN ();
    SSL_LIBRARY_INIT ();

    /* loop until PRNG has been seeded with enough data */

    while (!RAND_STATUS ())
    	{
#ifdef	WIN32
	QueryPerformanceCounter (&counter);
        RAND_ADD (&counter, sizeof (counter), 0.1); 
#else	/* WIN32 */
        if (clock_gettime (CLOCK_REALTIME, &ts) != 0)
	    {
	    ts.tv_sec  = 0;
	    ts.tv_nsec = 0;
	    }
        RAND_ADD (&ts.tv_nsec, sizeof (ts.tv_nsec), 0.1);
#endif	/* WIN32 */
	}

#ifndef	HOST
    _func_wrProxySslConnectionCreate = wrProxySslConnectionCreate;
    _func_wrProxySslConnectionDelete = wrProxySslConnectionDelete;
    _func_wrProxySslRead = wrProxySslRead;
    _func_wrProxySslWrite = wrProxySslWrite;
#endif	/* HOST */

    wrProxySslLibInitialized = TRUE;

    return OK;
    }

/*******************************************************************************
*
* wrProxySslConnectionCreate - Create a SSL connection
*
* This routine creates a SSL connection that supports the SSLv2, SSLv3,
* TLSv1 protocols and connect it to the <fd> file descriptor. If the <server>
* parameter is set to TRUE, the TLS/SSL connection is initialized as a server.
*
* RETURNS: A SSL connection cookie or NULL if not able to create a connection.
*
* ERRNO: N/A
*
* NOMANUAL
*/

void * wrProxySslConnectionCreate
    (
    int		fd,
    BOOL	server
    )
    {
    SSL_CTX *	pSslCtx = NULL;
    SSL *	pSsl = NULL;
    X509 *	pSslCert = NULL;
#ifdef	HOST
    RSA *	pPkey = NULL;
#else	/* HOST */
    EVP_PKEY *	pPkey = NULL;
#endif	/* HOST */
    char	file[PATH_MAX];
    FILE *	pFp = NULL;

    /*
     * Create a new SSL_CTX object as framework to establish TLS/SSL
     * enabled connections. A TLS/SSL connection established with the
     * SSLv23_method method will understand the SSLv2, SSLv3, and TLSv1
     * protocol.
     */

    if ((pSslCtx = SSL_CTX_NEW (SSLV23_METHOD ())) == NULL)
	{
	PRINT_ERR ("Unable to create SSL_CTX object: pSslCtx = %x\n", pSslCtx);
	return NULL;
	}

    SSL_CTX_SET_VERIFY (pSslCtx,
    			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			NULL);

#ifdef	HOST
    snprintf (file, sizeof (file), "%s/%s.key", certRepository, fileName);
    if ((pFp = fopen (file, "r")) == NULL)
	{
        PRINT_ERR ("Unable to open the %s file\n", file);
        goto wrProxySslConnectionCreateError;
        }
  
    if ((pPkey = PEM_READ_RSAPRIVATEKEY (pFp, NULL, NULL, NULL)) == NULL)
        {
        PRINT_ERR ("%s\n", ERR_ERROR_STRING (ERR_GET_ERROR (), NULL));
        fclose (pFp);
	goto wrProxySslConnectionCreateError;
	}

    fclose (pFp);

    snprintf (file, sizeof(file), "%s/%s.crt", certRepository, fileName);
#else	/* HOST */
    snprintf (file, sizeof (file), "%s.key", fileName);
    if ((pPkey = ipcom_key_db_pkey_get (file)) == IP_NULL)
	{
	PRINT_ERR ("Unable to get the %s private key\n", file);
	goto wrProxySslConnectionCreateError;
	}

    if (certRepository != NULL)
	snprintf (file, sizeof(file), "%s/%s.crt", certRepository, fileName);
    else
	snprintf (file, sizeof(file), "%s%s/%s.crt",
	          IPCOM_FILE_ROOT, fileName, fileName);
#endif	/* HOST */

    if (!SSL_CTX_LOAD_VERIFY_LOC (pSslCtx, file, NULL))
	{
	PRINT_ERR ("Unable to verify location\n", file);
	goto wrProxySslConnectionCreateError;
	}

    if ((pFp = fopen (file, "r")) == NULL)
	{
	PRINT_ERR ("Unable to open the %s file\n", file);
	goto wrProxySslConnectionCreateError;
	}

    if ((pSslCert = PEM_READ_X509 (pFp, NULL, NULL, NULL)) == NULL)
	{
	PRINT_ERR ("%s\n", ERR_ERROR_STRING (ERR_GET_ERROR (), NULL));
	fclose (pFp);
	goto wrProxySslConnectionCreateError;
	}

    fclose (pFp);

    /*
     * Create a new SSL structure which is needed to hold the data for a
     * a TLS/SSL connection. The new structure inherits the settings of the
     * the underlying context pSslCtx: connection method (SSLv2/v3/TLSv1),
     * options, verification settings, timeout settings.
     */

    if ((pSsl = SSL_NEW (pSslCtx)) == NULL)
	{
	PRINT_ERR ("Unable to create SSL_CTX object: pSsl = %x\n", pSsl);
	goto wrProxySslConnectionCreateError;
	}

    if (SSL_SET_FD (pSsl, fd) != 1)
	{
    	PRINT_ERR ("Unable to set SSL fd: pSsl = %x\n", pSsl);
	goto wrProxySslConnectionCreateError;
	}

    SSL_USE_CERTIFICATE (pSsl, pSslCert);
    SSL_USE_PRIVATEKEY (pSsl, pPkey);

    if (server)
	SSL_SET_ACCEPT_STATE (pSsl);
    else
	SSL_SET_CONNECT_STATE (pSsl);

    return ((void *) pSsl);

wrProxySslConnectionCreateError:

    if (pSslCtx != NULL)
	SSL_CTX_FREE (pSslCtx);

    return NULL;
    }

/*******************************************************************************
*
* wrProxySslConnectionDelete -	Delete a SSL connection
*
* This routine shutdowns the SSL connection associated to the <pCookie>. It
* also deletes all SSL structures.
*
* RETURNS: N/A
*
* ERRNO: N/A
*
* NOMANUAL
*/

void wrProxySslConnectionDelete
    (
    void * pCookie
    )
    {
    SSL *	pSsl = (SSL *) pCookie;
    SSL_CTX *	pSslCtx;

    if (pSsl == NULL)
    	return;

    SSL_SHUTDOWN (pSsl);

    if ((pSslCtx = SSL_GET_SSL_CTX (pSsl)) != NULL)
	SSL_CTX_FREE (pSslCtx);

    SSL_FREE(pSsl);
    }

/*******************************************************************************
*
* wrProxySslWrite - Write bytes to a SSL connection
*
* This routine writes <size> bytes from the buffer <buffer> into the <pCookie>
* SSL connection. If necessary, wrProxySslWrite will negotiate a TLS/SSL
* session. If the peer requests a re-negotiation, it will be performed
* transparently during the wrProxySslWrite operation.
*
* RETURNS: The number of bytes written to the SSL connection or ERROR.
*
* ERRNO: N/A
*
* NOMANUAL
*/

ssize_t wrProxySslWrite
    (
    void *	pCookie,
    char *	buffer,
    size_t	size
    )
    {
    return (wrProxySslRW (pCookie, buffer, size, TRUE));
    }

/*******************************************************************************
*
* wrProxySslRead - read bytes from a SSL connection
*
* This routine tries to read <size> bytes from the <pCookie> SSL connection
* into the buffer <buffer>. If necessary, wrProxySslRead will negotiate a
* TLS/SSL session. If the peer requests a re-negotiation, it will be performed
* transparently during the wrProxySslRead operation.
*
* RETURNS: The number of bytes read from the SSL connection or ERROR.
*
* ERRNO: N/A
*
* NOMANUAL
*/

ssize_t wrProxySslRead
    (
    void *	pCookie,
    char *	buffer,
    size_t	size
    )
    {
    return (wrProxySslRW (pCookie, buffer, size, FALSE));
    }

#ifndef	HOST
/*******************************************************************************
*
* wrProxySslCertGen - Generate certificate to be used by WR proxy
*
* This routine generates the authentication certificate and private key files
* for the WR proxy. These files will be used by both the WR proxy (SSL server)
* and the target server (SSL client) for authentication during a secure proxy
* communication.
*
* RETURNS: OK on success, ERROR if unable to generate authentication files
*
* ERRNO: N/A
*/

STATUS wrProxySslCertGen
    (
    char *	pPath,
    int		rsaKeyLength,
    char *	startDate,
    char *	endDate,
    long	numDays
    )
    {
    RSA *		pRsa = NULL;
    EVP_PKEY *		pRsaPkey = NULL;
    X509 *		pCert = NULL;
    ASN1_INTEGER *	pSerial = NULL;
    X509_NAME *		pName = NULL;
    FILE *		pFpPKey = NULL;
    FILE *		pFpCert = NULL;
    char		file[PATH_MAX];
    STATUS		status = ERROR;
    struct stat		st;
#ifndef	HOST
    Ip_err		err;
    int			savedErrno;
#endif	/* HOST */

    if (pPath == NULL)
	{
	fprintf (stderr, "A directory must be defined\n");
    	return ERROR;
	}

    if (rsaKeyLength == 0)
    	rsaKeyLength = PROXY_RSA_NUM_BITS;

    if ((startDate != NULL) || (endDate != NULL))
	{
	if (startDate == NULL)
	    {
	    fprintf (stderr, "A start date must be defined\n");
	    return ERROR;
	    }

	if (!ASN1_UTCTIME_set_string (NULL, startDate))
	    {
	    fprintf (stderr, "Start date is invalid, it should be "
	    	     "YYMMDDHHMMSSZ\n");
	    return ERROR;
	    }

	if (endDate == NULL)
	    {
	    fprintf (stderr, "A end date must be defined\n");
	    return ERROR;
	    }


	if (!ASN1_UTCTIME_set_string (NULL, endDate))
	    {
	    fprintf (stderr, "End date is invalid, it should be "
	    	     "YYMMDDHHMMSSZ\n");
    	    return ERROR;
	    }
	}
    else
	{
	/*
	 * startDate will be the current calendar time (i.e value returned by
	 * time()).
	 */

    	startDate="today";

	if (numDays == 0)
    	    numDays = 365L * 10L;
	}

    /* Generate a RSA key pair */

    if ((pRsa = RSA_generate_key (rsaKeyLength, PROXY_RSA_EXP,
    				  NULL, (void *)"RSA")) == NULL)
	{
	fprintf (stderr, "Failed to generate a RSA key\n");
	goto wrProxySslCertGenExit;
	}

    /* Validate RSA keys */

    if (RSA_check_key (pRsa) != 1)
	{
	fprintf (stderr, "RSA key are not valid\n");
	goto wrProxySslCertGenExit;
	}

    /*
     * Allocate an empty EVP_PKEY structure which is used by OpenSSL
     * to store private keys and assign it to pRsa.
     */

    if ((pRsaPkey = EVP_PKEY_new ()) == NULL)
    	{
	fprintf (stderr, "Failed to allocate EVP_PKEY structure\n");
	goto wrProxySslCertGenExit;
	}
    EVP_PKEY_assign_RSA (pRsaPkey, pRsa);


    /* Allocate and initialize a X509 structure */

    if ((pCert = X509_new ()) == NULL) 
    	{
	fprintf (stderr, "Failed to allocate X509 certificate\n");
	goto wrProxySslCertGenExit;
	}

    X509_set_version (pCert, 2L);
    pSerial = ASN1_INTEGER_new ();
    ASN1_INTEGER_set (pSerial, 1);
    X509_set_serialNumber (pCert, pSerial);
    ASN1_INTEGER_free (pSerial);

    if (strcmp(startDate,"today") == 0)
	X509_gmtime_adj(X509_get_notBefore (pCert), 0);
    else
	ASN1_UTCTIME_set_string(X509_get_notBefore (pCert), startDate);

    if (endDate == NULL)
	X509_gmtime_adj(X509_get_notAfter (pCert), (long) 60*60*24*numDays);
    else
	ASN1_UTCTIME_set_string(X509_get_notAfter (pCert), endDate);

    pName = X509_get_subject_name (pCert);
    X509_NAME_add_entry_by_txt (pName, "commonName", MBSTRING_ASC,
    		(unsigned char *) subjectName,
					(int) strlen (subjectName), -1, 0);
    pName = X509_get_issuer_name (pCert);
    X509_NAME_add_entry_by_txt (pName, "commonName", MBSTRING_ASC,
    		(unsigned char *)issuerName, (int) strlen(issuerName), -1, 0);

    if (!X509_set_pubkey (pCert, pRsaPkey))
    	{
	fprintf (stderr, "Failed to set the public key\n");
	goto wrProxySslCertGenExit;
	}
    X509_sign (pCert, pRsaPkey, EVP_sha1());
    if (!X509_verify(pCert, pRsaPkey))
	goto wrProxySslCertGenExit;

    /*
     * NOTE: Ideally, we should test here that the given path is valid using
     * stat(). But this does not work with netDrv which fails to open a
     * directory... (This is a known netDrv limitation).
     */

#ifdef	HOST
    if ((stat (pPath, &st) != OK) &&
#ifdef	WIN32
	(_mkdir (pPath) != OK))
#else	/* WIN32 */
	(mkdir (pPath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != OK))
#endif	/* WIN32 */
    	{
	fprintf (stderr, "Unable to create the %s directory\n", pPath);
	goto wrProxySslCertGenExit;
	}
#endif	/* HOST */

#ifndef	HOST
    snprintf (file, sizeof(file), "%s.key", fileName);

    savedErrno = errnoGet();
importKeyAgain:
    if ((err = ipcom_key_db_pkey_import (file, pRsaPkey)) != IPCOM_SUCCESS)
    	{
	/*
	 * If the key already exists then delete it and try to import it
	 * again.
	 */

	if ((err == IPCOM_ERR_ALREADY_INSTALLED) &&
	    (ipcom_key_db_pkey_del (file) == IPCOM_SUCCESS))
	    goto importKeyAgain;

	fprintf (stderr, "Unable to import private key in key database.\n");
	goto wrProxySslCertGenExit;
	}
    errnoSet (savedErrno);
#endif	/* HOST */

    snprintf (file, sizeof(file), "%s/%s.key", pPath, fileName);
    if ((pFpPKey = fopen (file, "w")) == NULL)
    	{
	fprintf (stderr, "Unable to open the %s file for write ops.\n", file);
	goto wrProxySslCertGenExit;
	}

    if (!PEM_write_PKCS8PrivateKey (pFpPKey, pRsaPkey,
    					NULL, NULL, 0, NULL, NULL))
	goto wrProxySslCertGenExit;

#ifndef	HOST
    if (certRepository == NULL)
	{
	snprintf (file, sizeof(file), "%s%s", IPCOM_FILE_ROOT, fileName);

	savedErrno = errnoGet();
	if (stat (file, &st) != OK)
	    {
	    errnoSet (savedErrno);

	    if (mkdir (file) != OK)
		{
		fprintf (stderr, "Unable to create the %s directory\n", file);
		goto wrProxySslCertGenExit;
		}
	    }
	snprintf (file, sizeof(file), "%s%s/%s.crt",
		  IPCOM_FILE_ROOT, fileName, fileName);
	}
    else
	snprintf (file, sizeof(file), "%s/%s.crt",
		  certRepository, fileName);

    if ((pFpCert = fopen (file, "w")) == NULL)
    	{
	fprintf (stderr, "Unable to open the %s file for write ops.\n", file);
	goto wrProxySslCertGenExit;
	}

    PEM_write_X509 (pFpCert, pCert);
    fclose (pFpCert);
#endif	/* HOST */

    snprintf (file, sizeof(file), "%s/%s.crt", pPath, fileName);
    if ((pFpCert = fopen (file, "w")) == NULL)
    	{
	fprintf (stderr, "Unable to open the %s file for write ops.\n", file);
	goto wrProxySslCertGenExit;
	}

    PEM_write_X509 (pFpCert, pCert);

    status = OK;

wrProxySslCertGenExit:
    if (pCert != NULL)
    	X509_free (pCert);

    if (pRsa != NULL)
    	RSA_free (pRsa);

    if (pFpPKey != NULL)
	fclose (pFpPKey);
    if (pFpCert != NULL)
	fclose (pFpCert);

    return (status);
    }
#endif	/* HOST */

/*******************************************************************************
*
* wrProxySslRW - read/write bytes from/to a SSL connection
*
* If <write> is FALSE, this routine tries to read <size> bytes from the
* <pCookie> SSL connection into the buffer <buffer>, otherwise it writes
* <size> bytes from the buffer <buffer> into the <pCookie> SSL connection.
* If necessary, wrProxySslRW will negotiate a TLS/SSL session. If the peer
* requests a re-negotiation, it will be performed transparently during the
* wrProxySslRW operation.
*
* RETURNS: The number of bytes read/write from/to the SSL connection or ERROR.
*
* ERRNO: N/A
*
* NOMANUAL
*/

LOCAL ssize_t wrProxySslRW
    (
    void *	pCookie,
    char *	buffer,
    size_t	size,
    BOOL	write
    )
    {
    SSL *	pSsl = (SSL *) pCookie;
    fd_set	readFds;
    fd_set	writeFds;
    fd_set	errFds;
    int		retVal;
    int		err;

    if (pCookie == NULL)
    	return ERROR;

again:
    if (write)
	retVal = SSL_WRITE (pSsl, buffer, (int) size);
    else
	retVal = SSL_READ (pSsl, buffer, (int) size);

    if (retVal > 0)
    	return ((ssize_t) retVal);

    /*
     * Read/Write operation was not successful. Call SSL_get_error() with the
     * return value <retVal> to find out, whether an error occurred or the
     * connection was shut down cleanly.
     */

    err = SSL_GET_ERROR (pSsl, retVal);

    /*
     * As at any time a re-negotiation is possible, a call to SSL_read/write()
     * can also cause write/read operations! The calling process then must
     * repeat the call after the required operation is done (we're using
     * select to know when the operation is done).
     */
     
    if ((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE))
	{
	int	fd = SSL_GET_FD (pSsl);

	FD_ZERO (&readFds);
	FD_ZERO (&writeFds);
	FD_ZERO (&errFds);

	if (wrProxySslLibDebug)
	    fprintf (stderr, "SSL_%s returned %s\n", (write ? "write" : "read"),
		 ((err == SSL_ERROR_WANT_READ) ?
		  "SSL_ERROR_WANT_READ" : "SSL_ERROR_WANT_WRITE"));

	if (err == SSL_ERROR_WANT_READ)
	    FD_SET (fd, &readFds);
	if (err == SSL_ERROR_WANT_WRITE)
	    FD_SET (fd, &writeFds);
	FD_SET (fd, &errFds);

	retVal = select (FD_SETSIZE, &readFds, &writeFds, &errFds, NULL);

	if (retVal != ERROR)
    	    goto again;
	}
    else
	{
	if (wrProxySslLibDebug)
	    fprintf (stderr, "%s\n", ERR_ERROR_STRING (ERR_GET_ERROR (), NULL));
	}

    return ERROR;
    }
