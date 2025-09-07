/*
 ******************************************************************************
 *                     INTERPEAK INTERNAL API HEADER FILE
 *
 *   Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto_h.h,v $ $Revision: 1.2 $
 *   $Source: /home/interpeak/CVSRoot/ipcrypto/src/ipcrypto_h.h,v $
 *   $Author: roger $ $Date: 2007-05-11 07:50:07 $
 *   $State: Exp $ $Locker:  $
 *
 *   Copyright Interpeak AB 2000-2003 <www.interpeak.se>. All rights reserved.
 *     Design and implementation by Roger Boden <roger@interpeak.se>
 ******************************************************************************
 */
#ifndef IPCRYPTO_H_H
#define IPCRYPTO_H_H

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

#include <ipcom_type.h>
#include <ipcom_cstyle.h>
#include <ipcom_os.h>


#ifdef __cplusplus
extern "C" {
#endif

/*
 ****************************************************************************
 * 4                    DEFINES
 ****************************************************************************
 */

/*
 *===========================================================================
 *                         syslog
 *===========================================================================
 */
#define IPCOM_SYSLOG_PRIORITY    IPCRYPTO_SYSLOG_PRIORITY
#define IPCOM_SYSLOG_FACILITY    IPCOM_LOG_IPCRYPTO


/*
 ****************************************************************************
 * 5                    TYPES
 ****************************************************************************
 */

    struct Ipcrypto_data_st
    {
        Ipcom_mutex* crypto_locks;
    };

    typedef struct Ipcrypto_data_st Ipcrypto_data;

    IP_EXTERN Ipcrypto_data ipcrypto;

/*
 ****************************************************************************
 * 6                    FUNCTIONS
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
