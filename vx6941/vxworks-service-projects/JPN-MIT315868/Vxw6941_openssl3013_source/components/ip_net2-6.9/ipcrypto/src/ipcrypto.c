/*
 ******************************************************************************
 *                     INTERPEAK SOURCE FILE
 *
 *   Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto.c,v $ $Revision: 1.26 $
 *   $Source: /home/interpeak/CVSRoot/ipcrypto/src/ipcrypto.c,v $
 *   $Author: rboden $
 *   $State: Exp $ $Locker:  $
 *
 *   INTERPEAK_COPYRIGHT_STRING
 *   Design and implementation by Roger Boden <roger@interpeak.se>
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

#ifdef IPCOM_DMALLOC_C
#undef IPCOM_DMALLOC_C
#endif


/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */

#define IPCOM_USE_CLIB_PROTO
#include <ipcom_type.h>
#include <ipcom_clib.h>
#include <ipcom_err.h>
#include <ipcom_syslog.h>
#include <ipcom_autoconf.h>

#include <e_os.h>
#include <ipcrypto_config.h>
#include "ipcrypto_h.h"

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/bio.h"
#include "openssl/conf.h"
#include "openssl/evp.h"
#ifndef OPENSSL_NO_ENGINE
#include "openssl/engine.h"
#endif

/*
 ****************************************************************************
 * 4                    EXTERN PROTOTYPES
 ****************************************************************************
 */

#ifdef OPENSSL_FIPS
unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len);
#endif

/*
 ****************************************************************************
 * 5                    DEFINES
 ****************************************************************************
 */



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

IP_PUBLIC const char *ipcrypto_version(void);

IP_STATIC void ipcrypto_lock_callback(int mode, int type, const char* file, int line);

IPCOM_PROCESS(ipcrypto_rnd_seed);

IP_GLOBAL int ipcrypto_cmd_memory(int argc, char **argv);

IP_PUBLIC void ipcrypto_cmds_startup(void);

IP_PUBLIC Ip_err ipcrypto_create(void);

IP_PUBLIC Ip_err ipcrypto_start(void);

void OPENSSL_init(void);

/*void OPENSSL_init_crypto(void);*/
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);

/*
 ****************************************************************************
 * 8                    DATA
 ****************************************************************************
 */

CONF *ipcrypto_config = IP_NULL;

#if 1
#ifndef IP_PORT_LAS
BIO *bio_err = IP_NULL;
#endif
#endif

char *default_config_file = IPCRYPTO_DEFAULT_CONFIG_FILE;
Ipcrypto_data ipcrypto;

int in_FIPS_mode=0;

#ifdef OPENSSL_FIPS
extern unsigned char              FIPS_signature[20];
extern unsigned char              ipcrypto_fips_signature[20];
#endif

/*
 ****************************************************************************
 * 9                    LOCAL FUNCTIONS
 ****************************************************************************
 */

/*
 *===========================================================================
 *                    ipcrypto_setup_lock_functions
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC Ip_err
ipcrypto_setup_lock_functions(void)
{
    int i;

    ipcrypto.crypto_locks = ipcom_malloc(sizeof(Ipcom_mutex)*CRYPTO_NUM_LOCKS);
    if(!ipcrypto.crypto_locks)
        return IPCOM_ERR_FAILED;

    for(i=0; i<CRYPTO_NUM_LOCKS; i++)
    {
        if(ipcom_mutex_create(&(ipcrypto.crypto_locks[i])) != IPCOM_SUCCESS)
        {
            while(i>0)
            {
                ipcom_mutex_delete(&(ipcrypto.crypto_locks[i]));
                i--;
            }
            return IPCOM_ERR_FAILED;
        }
    }

    CRYPTO_set_locking_callback(ipcrypto_lock_callback);

    return IPCOM_SUCCESS;
}


/*
 *===========================================================================
 *                    ipcrypto_lock_callback
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void
ipcrypto_lock_callback(int mode, int type, const char *file, int line)
{
    (void)file;
    (void)line;

    ip_assert(type < CRYPTO_NUM_LOCKS);
    ip_assert((mode & CRYPTO_LOCK) || (mode & CRYPTO_UNLOCK));

    if(type >= CRYPTO_NUM_LOCKS)
        return;

    if(mode & CRYPTO_UNLOCK)
    {
        ipcom_mutex_unlock(ipcrypto.crypto_locks[type]);
    }

    if(mode & CRYPTO_LOCK)
    {
        ipcom_mutex_lock(ipcrypto.crypto_locks[type]);
    }
}


/*
 *===========================================================================
 *                    ipcrypto_rnd_seed
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IPCOM_PROCESS(ipcrypto_rnd_seed)
{
    Ip_u32 i, tmp;

    ipcom_proc_init();

    while(ipcom_random_seed_state() != 100)
    {
        tmp = ipcom_random();
        RAND_seed((char *) &tmp, 4);
        ipcom_sleep(1); /* Wait for some entryphy to be gathered */
    }

    for(i=0; i<5; i++)
    {
        tmp = ipcom_random();
        RAND_seed((char*) &tmp, 4);
    }

    ipcom_proc_exit();
}


/*
 *===========================================================================
 *                         ipcrypto_cmd_memory
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
#ifdef IPCRYPTO_USE_TEST
IP_GLOBAL int
ipcrypto_cmd_memory(int argc, char **argv)
{
#ifdef CRYPTO_MDEBUG
    BIO *bio_out;

    (void)argc;
    (void)argv;

    MemCheck_off();
    bio_out = BIO_new_fp(ip_stdout, BIO_NOCLOSE);
    MemCheck_on();

    CRYPTO_mem_leaks(bio_out);
    (void)BIO_flush(bio_out);

    BIO_free(bio_out);
#else
    (void)argc;
    (void)argv;
#endif
    return 0;
}
#endif /* IPCRYPTO_USE_TEST */


/*
 *===========================================================================
 *                         ipcrypto_dmalloc
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
#ifdef IPCOM_USE_DMALLOC
IP_STATIC void *
ipcrypto_dmalloc(Ip_size_t num, const char *file, int line)
{
    return ipcom_dmalloc(num, file, IP_NULL, line);
}


/*
 *===========================================================================
 *                         ipcrypto_drealloc
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC void *
ipcrypto_drealloc(void *old_ptr, Ip_size_t num, const char *file, int line)
{
    return ipcom_drealloc(old_ptr, num, file, IP_NULL, line);
}
#endif /* IPCOM_USE_DMALLOC */


/*
 ****************************************************************************
 * 10                   PUBLIC FUNCTIONS
 ****************************************************************************
 */

/*
 *===========================================================================
 *                    ipcrypto_cmds_startup
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_PUBLIC void
ipcrypto_cmds_startup(void)
{
#ifndef IP_PORT_LAS
    /* Free&clear global variable bio_err for new logins. */
    if (bio_err != IP_NULL)
    {
        BIO_free(bio_err);
        bio_err = IP_NULL;
    }
#endif
}


/*
 *===========================================================================
 *                         ipcrypto_create
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_PUBLIC Ip_err
ipcrypto_create(void)
{
    static int init = 1;
    char uninitialized_buf[32];

    if(init == 0)
    {
        int ret;
        init = 1;

        /* Set memory allocation function callbacks. */
#ifdef IPCOM_USE_DMALLOC
        ret = CRYPTO_set_mem_ex_functions(ipcrypto_dmalloc, ipcrypto_drealloc, ipcom_dfree);
#else
        ret = CRYPTO_set_mem_functions(ipcom_malloc, ipcom_realloc, ipcom_free);
#endif
        (void) ret;
        ip_assert(ret);

        if(ipcrypto_setup_lock_functions() != IPCOM_SUCCESS)
            return IPCOM_ERR_FAILED;

        OpenSSL_add_all_algorithms();

        /* Init things so we will get meaningful error messages rather than numbers. */
        ERR_load_crypto_strings();

#ifndef OPENSSL_NO_ENGINE
        ENGINE_load_builtin_engines();
#endif

        /* Dummy seed to make RAND functions operational */
#ifdef IPVALGRIND
        ipcom_memset(uninitialized_buf, 0, sizeof(uninitialized_buf));
#endif
        RAND_seed((char *) uninitialized_buf, sizeof(uninitialized_buf));

#ifdef OPENSSL_FIPS
        {
            unsigned int i;
            Ip_bool enable_fips = IP_FALSE;
#if defined(IP_DEBUG) || defined(IPTESTENGINE)
            int len;

            len=FIPS_incore_fingerprint(ipcrypto_fips_signature, sizeof(ipcrypto_fips_signature));
            if (len!=sizeof(ipcrypto_fips_signature))
            {
                IPCOM_LOG0(ERR, "FIPS_incore_fingerprint() failed");
                return IPCOM_ERR_FAILED;
            }
#endif
            for (i=0; i<sizeof(ipcrypto_fips_signature); i++)
            {
                if (ipcrypto_fips_signature[i] != 0xEE)
                {
                    enable_fips = IP_TRUE;
                    break;
                }
            }
            if (enable_fips)
            {
                ipcom_memcpy(FIPS_signature, ipcrypto_fips_signature, sizeof(FIPS_signature));
                FIPS_mode_set(1);
            }
        }
#endif
    }

    return IPCOM_SUCCESS;
}


/*
 *===========================================================================
 *                    ipcrypto_start
 *===========================================================================
 */
IP_PUBLIC Ip_err
ipcrypto_start(void)
{
    Ipcom_proc_attr proc_attr;

    ipcom_proc_attr_init(&proc_attr);
    proc_attr.stacksize = IPCOM_PROC_STACK_SMALL;
    proc_attr.flags = IPCOM_PROC_FLAG_FP;
		
#if 0
    (void)ipcom_proc_acreate("ipcrypto_rnd_seed", ipcrypto_rnd_seed, &proc_attr, IP_NULL);
#endif

    return IPCOM_SUCCESS;
}


/*
 *===========================================================================
 *                    ipcrypto_version
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_PUBLIC const char *
ipcrypto_version(void)
{
#ifdef OPENSSL_FIPS
    return "@(#) IPCRYPTO FIPS 140-2 $Name: VXWORKS_ITER29_2014062011 $ - INTERPEAK_COPYRIGHT_STRING";
#else
    return "@(#) IPCRYPTO $Name: VXWORKS_ITER29_2014062011 $ - INTERPEAK_COPYRIGHT_STRING";
#endif
}


void
OPENSSL_init(void)
{
    /* Dummy function to make the linker happy */
}

#if 0
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
    /* Dummy function to make the linker happy */
}
#endif
/*
 ****************************************************************************
 *                      END OF FILE
 ****************************************************************************
 */

