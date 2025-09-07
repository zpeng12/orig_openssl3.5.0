/*
 ******************************************************************************
 *                     INTERPEAK SOURCE FILE
 *
 *   Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto_cmd_fips_ctrl.c,v $ $Revision: 1.3 $
 *   $Source: /home/interpeak/CVSRoot/ipcrypto/src/ipcrypto_cmd_fips_ctrl.c,v $
 *   $Author: rboden $
 *   $State: Exp $ $Locker:  $
 *
 *   INTERPEAK_COPYRIGHT_STRING
 *   Design and implementation by Roger Boden <roger.boden@windriver.com>
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

#ifdef OPENSSL_FIPS

/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */
#define IPCOM_USE_CLIB_PROTO
#include <ipcom_type.h>
#include <ipcom_cstyle.h>
#include <ipcom_clib.h>
#include <ipcom_err.h>

#include <openssl/fips.h>

/*
 ****************************************************************************
 * 4                    DEFINES
 ****************************************************************************
 */

#define IPCRYPTO_CMD_FIPS_CTRL_MODE 1
#define IPCRYPTO_CMD_FIPS_CTRL_HASH 2

#define IPCRYPTO_CMD_FIPS_CTRL_MODE_ON   10
#define IPCRYPTO_CMD_FIPS_CTRL_MODE_OFF  11
#define IPCRYPTO_CMD_FIPS_CTRL_MODE_SHOW 12

#define bin2ascii(c) ((c)>=10?(((c)-10)+'A'):((c)+'0'))

/*
 ****************************************************************************
 * 5                    TYPES
 ****************************************************************************
 */
struct Ipcrypto_cmd_fips_ctrl_str_map_st
{
    const char* name;
    int value;
};
typedef struct Ipcrypto_cmd_fips_ctrl_str_map_st Ipcrypto_cmd_fips_ctrl_str_map;

/*
 ****************************************************************************
 * 6                    EXTERN PROTOTYPES
 ****************************************************************************
 */
unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len);

/*
 ****************************************************************************
 * 7                    LOCAL PROTOTYPES
 ****************************************************************************
 */
IP_STATIC void
ipcrypto_cmd_fips_ctrl_usage(void)
{
    ipcom_printf("fips_ctrl command [args]\n"
                 "    The following commands are supported:\n"
                 "     - mode <on|off|show>   Sets the FIPS mode on or off, \n"
                 "                            or prints current mode\n"
                 "     - hash                 Prints incore hash value of\n"
                 "                            the FIPS module\n");
}


/*
 ****************************************************************************
 * 8                    DATA
 ****************************************************************************
 */
Ipcrypto_cmd_fips_ctrl_str_map cmd_str_map [] =
    { {"mode", IPCRYPTO_CMD_FIPS_CTRL_MODE},
      {"hash", IPCRYPTO_CMD_FIPS_CTRL_HASH},
      {IP_NULL, -1} };

Ipcrypto_cmd_fips_ctrl_str_map mode_str_map [] =
    { {"on", IPCRYPTO_CMD_FIPS_CTRL_MODE_ON},
      {"off", IPCRYPTO_CMD_FIPS_CTRL_MODE_OFF},
      {"show", IPCRYPTO_CMD_FIPS_CTRL_MODE_SHOW},
      {IP_NULL, -1} };

/*
 ****************************************************************************
 * 9                    STATIC FUNCTIONS
 ****************************************************************************
 */


/*
 *===========================================================================
 *                    ipcrypto_cmd_fips_ctrl_do_mode
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC int
ipcrypto_cmd_fips_ctrl_do_mode(const char* sub_cmd)
{
    int mode_cmd = 0;
    Ipcrypto_cmd_fips_ctrl_str_map *str_map = mode_str_map;

    while (str_map->name)
    {
        if (ipcom_strcmp(str_map->name, sub_cmd) == 0)
        {
            mode_cmd = str_map->value;
        }
        str_map++;
    }

    if (mode_cmd == 0)
    {
        ipcom_printf("Unknown mode sub-command: %s\n", sub_cmd);
        ipcrypto_cmd_fips_ctrl_usage();
        return -IP_ERRNO_EINVAL;
    }

    switch (mode_cmd)
    {
    case IPCRYPTO_CMD_FIPS_CTRL_MODE_ON:
        if (FIPS_mode())
        {
            ipcom_printf("Already in FIPS mode\n");
            return IPCOM_ERR_FAILED;
        }
        RAND_set_rand_method(IP_NULL);
        if (!FIPS_mode_set(1))
        {
            ipcom_printf("Failed to enable FIPS mode\n");
            return IPCOM_ERR_FAILED;
        }
        ipcom_printf("FIPS mode on\n");
        return IPCOM_SUCCESS;

    case IPCRYPTO_CMD_FIPS_CTRL_MODE_OFF:
        if (!FIPS_mode())
        {
            ipcom_printf("Not in FIPS mode\n");
            return IPCOM_ERR_FAILED;
        }
        if (!FIPS_mode_set(0))
        {
            ipcom_printf("Failed to disable FIPS mode\n");
            return IPCOM_ERR_FAILED;
        }
        ipcom_printf("FIPS mode off\n");
        return IPCOM_SUCCESS;

    case IPCRYPTO_CMD_FIPS_CTRL_MODE_SHOW:
        if (FIPS_mode())
            ipcom_printf("FIPS mode on\n");
        else
            ipcom_printf("FIPS mode off\n");
        return IPCOM_SUCCESS;

    default:
        IP_PANIC();
        return IPCOM_ERR_FAILED;
    }

    return IPCOM_ERR_FAILED;
}


/*
 *===========================================================================
 *                    ipcrypto_cmd_fips_ctrl_do_hash
 *===========================================================================
 * Description:
 * Parameters:
 * Returns:
 *
 */
IP_STATIC int
ipcrypto_cmd_fips_ctrl_do_hash(void)
{
    unsigned char sig[20];
    int i;
    int len;

    len=FIPS_incore_fingerprint (sig,sizeof(sig));
    if (len!=sizeof(sig))
    {
        ipcom_printf("Failed to calculate incore hash of FIPS module\n");
        return IPCOM_ERR_FAILED;
    }

    for (i=0; i<sizeof(sig); i++)
        ipcom_printf("0x%c%c, ", bin2ascii(sig[i]>>4), bin2ascii(sig[i]&0xf));
    ipcom_printf("\n");

    return IPCOM_SUCCESS;
}


/*
 ****************************************************************************
 * 10                   GLOBAL FUNCTIONS
 ****************************************************************************
 */
IP_GLOBAL int
ipcrypto_cmd_fips_ctrl(int argc, char** argv)
{
    int cmd = 0;
    Ipcrypto_cmd_fips_ctrl_str_map *str_map = cmd_str_map;

    if (argc < 2)
    {
        ipcrypto_cmd_fips_ctrl_usage();
        return -IP_ERRNO_EINVAL;
    }

    while (str_map->name)
    {
        if (ipcom_strcmp(str_map->name, argv[1]) == 0)
            cmd = str_map->value;
        str_map++;
    }

    if (cmd == 0)
    {
        ipcom_printf("Unknown command: %s\n", argv[1]);
        ipcrypto_cmd_fips_ctrl_usage();
        return -IP_ERRNO_EINVAL;
    }

    if (cmd == IPCRYPTO_CMD_FIPS_CTRL_MODE)
    {
        if (argc != 3)
        {
            ipcrypto_cmd_fips_ctrl_usage();
            return -IP_ERRNO_EINVAL;
        }

        return ipcrypto_cmd_fips_ctrl_do_mode(argv[2]);
    }

    if (cmd == IPCRYPTO_CMD_FIPS_CTRL_HASH)
    {
        if (argc != 2)
        {
            ipcrypto_cmd_fips_ctrl_usage();
            return -IP_ERRNO_EINVAL;
        }
        return ipcrypto_cmd_fips_ctrl_do_hash();

    }

    /* We should never get here */
    IP_PANIC();
    return -1;
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

#endif /* OPENSSL_FIPS */
