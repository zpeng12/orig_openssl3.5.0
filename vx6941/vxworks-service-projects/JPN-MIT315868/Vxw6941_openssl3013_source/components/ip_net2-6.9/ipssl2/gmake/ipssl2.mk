#############################################################################
#			      IPSSL.MK
#
#     Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipssl2.mk,v $ $Revision: 1.9.16.1 $
#     $Source: /home/interpeak/CVSRoot/ipssl2/gmake/ipssl2.mk,v $
#     $Author: svc-cmnet $ $Date: 2013-03-13 07:45:45 $
#     $State: Exp $ $Locker:  $
#
#     INTERPEAK_COPYRIGHT_STRING
#
#############################################################################


#############################################################################
# PRODUCT
###########################################################################

IPPROD ?= ipssl



#############################################################################
# CONFIGURATION
###########################################################################

ifeq ($(IPCRYPTO_OPENSSL_1_0_1),yes)
  OPENSSL_VER = openssl-1_0_1
else
  OPENSSL_VER = openssl-3_0_13
endif
IPSSL_OPENSSL_ROOT = $(IPSSL_ROOT)/$(OPENSSL_VER)

#############################################################################
# DEFINE
###########################################################################

IPDEFINE += -DIPSSL

#IPLIBDEFINE += -nostdinc

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

#############################################################################
# INCLUDE
###########################################################################

IPINCLUDE += -I$(IPSSL_ROOT)/config
IPINCLUDE += -I$(IPSSL_ROOT)/include
IPINCLUDE += -I$(IPSSL_OPENSSL_ROOT)/include

IPLIBINCLUDE += -I$(IPXINC_ROOT)/include
IPLIBINCLUDE += -I$(IPCRYPTO_ROOT)/$(OPENSSL_VER)/include
IPLIBINCLUDE += -I$(IPCRYPTO_ROOT)/$(OPENSSL_VER)


#############################################################################
# OBJECTS
###########################################################################

# Configuration
IPLIBOBJECTS_C += ipssl_config.o

# Main
IPLIBOBJECTS += ipssl.o
IPLIBOBJECTS += ipssl_cmds.o

include $(IPSSL_OPENSSL_ROOT)/gmake/ipssl_openssl_objs.mk


# Compiles the xxx_config.o if the $SKIP_CONFIG macro is either not defined
# or set to anything other than true.
ifneq ($(SKIP_CONFIG),true)
IPLIBOBJECTS    += $(IPLIBOBJECTS_C)
endif

#############################################################################
# SOURCE
###########################################################################

IPSRCDIRS += $(IPSSL_ROOT)/src
IPSRCDIRS += $(IPSSL_ROOT)/config
IPSRCDIRS += $(IPSSL_OPENSSL_ROOT)/apps
IPSRCDIRS += $(IPSSL_OPENSSL_ROOT)/ssl


#############################################################################
# LIB
###########################################################################

IPLIBS += $(IPLIBROOT)/libipssl.a


###########################################################################
# END OF IPSSL2.MK
###########################################################################
