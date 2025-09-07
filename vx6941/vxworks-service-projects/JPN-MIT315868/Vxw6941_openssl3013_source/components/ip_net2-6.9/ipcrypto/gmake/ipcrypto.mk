#############################################################################
#			      IPCRYPTO.MK
#
#     Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto.mk,v $ $Revision: 1.33.10.1 $
#     $Source: /home/interpeak/CVSRoot/ipcrypto/gmake/ipcrypto.mk,v $
#     $Author: svc-cmnet $ $Date: 2013-03-13 07:45:19 $
#     $State: Exp $ $Locker:  $
#
#     INTERPEAK_COPYRIGHT_STRING
#
#############################################################################
IPPROD ?= ipcrypto

#############################################################################
# BUILD CONFIGURATION
#############################################################################

include $(IPCRYPTO_ROOT)/gmake/ipcrypto_config.mk

#############################################################################
# DEFINE
###########################################################################

IPDEFINE += -DIPCRYPTO
IPIPDEFINE += -DIPCRYPTO_USE_TYPE_MAPPING
ifeq ($(IPPORT),unix)
IPLIBDEFINE += -Wno-unused-parameter
endif
ifeq ($(IPBUILD),debug)
IPDEFINE	+= -DCRYPTO_MDEBUG
endif

ifeq ($(IPBUILD),speed)
IPDEFINE	+= -DNO_ERR
endif

ifeq ($(IPVALGRIND),yes)
IPLIBDEFINE	+= -DPURIFY
endif

ifeq ($(IPCRYPTO_USE_FIPS),yes)
  IPDEFINE    += -DOPENSSL_FIPS
endif

IPLIBDEFINE	+= -DIPCOM_DMALLOC_C

#############################################################################
# INCLUDE
###########################################################################

IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/config
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/include
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/openssl-3_0_13/apps/include
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/openssl-3_0_13/include/openssl
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/openssl-3_0_13/include/internal
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/openssl-3_0_13/include/crypto
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/openssl-3_0_13/apps
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/openssl-3_0_13/providers/implementations/include/prov
IPINCLUDE 	+= -I$(IPCRYPTO_ROOT)/openssl-3_0_13/providers/common/include/prov

IPLIBINCLUDE 	+= -I$(IPXINC_ROOT)/include


#############################################################################
# OBJECTS
###########################################################################

# Configuration
IPLIBOBJECTS_C += ipcrypto_config.o


# Compiles the xxx_config.o if the $SKIP_CONFIG macro is either not defined
# or set to anything other than true.
ifneq ($(SKIP_CONFIG),true)
IPLIBOBJECTS    += $(IPLIBOBJECTS_C)
endif


#############################################################################
# IPCRYPTO_UOBJ
#############################################################################

# src files
IPLIBOBJECTS	+= ipcrypto.o
IPLIBOBJECTS	+= ipcrypto_bubble_babble.o
IPLIBOBJECTS	+= ipcrypto_cmd_cmp.o
IPLIBOBJECTS	+= ipcrypto_crc32.o
IPLIBOBJECTS	+= ipcrypto_aescmac.o
IPLIBOBJECTS	+= ipcrypto_aeskeywrap.o
#IPLIBOBJECTS	+= ipcrypto_key_db_example_keys.o
IPLIBOBJECTS	+= ipcrypto_rsa_oaep.o

include $(IPCRYPTO_OPENSSL_ROOT)/gmake/ipcrypto_openssl_objs.mk

#############################################################################
# SOURCE
###########################################################################

IPSRCDIRS 	+= $(IPCRYPTO_ROOT)/src
IPSRCDIRS 	+= $(IPCRYPTO_ROOT)/config



#############################################################################
# LIB
###########################################################################


ifeq ($(IPCRYPTO_USE_FIPS),yes)
IPLIBS += $(IPLIBROOT)/libipcrypto_fips.a
endif
ifneq ($(IPPORT),itron)
IPLIBS += $(IPLIBROOT)/libipcrypto_apps.a
endif
IPLIBS += $(IPLIBROOT)/libipcrypto.a

###########################################################################
# END OF IPCRYPTO.MK
###########################################################################
