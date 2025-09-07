# Makefile for Wind River Wireless Ethernet driver
#
# modification history
# --------------------
# 01l,23sep10,hfc  remove support of non-Vxbus wifi drivers
# 01k,22jan10,uol  Adding ipssl2 include path, required when using
#                  ipcom_pautoconf.h.
# 01j,16oct08,hfc  fix for defect WIND00139230
# 01i,16sep08,dwb  Fix for WIND00134302
# 01h,10jul08,hfc  replace findstring SMP with _WRS_CONFIG_SMP to adopt vsb
#                  notion
# 01g,27feb08,hfc  add support for atheros vxbus/smp driver 
# 01f,28jun07,spw  Disable SMP builds
# 01e,31aug05,dxb  Now look for install.h to verify SNMP is installed AND
#                  built.
# 01d,15aug05,rb  Tweak timestamp for 2.1.1 release
# 01c,01jun05,dxb  Added "man" target for Cyclops doc build.
# 01b,17aug04,dxb  Added rule to build objects only when SNMP present.
# 01a,28apr04,dxb  Created.
#
# DESCRIPTION
# This file contains the Makefile rules for building the Wind River
# 802dot11 MIB files.

TGT_DIR = $(WIND_BASE)/target
LIB_BASE_NAME = wlanVxbEnd
include $(TGT_DIR)/h/make/defs.library

ifndef _WRS_CONFIG_WLAN_ATH
all : rclean
endif

# If SNMP was installed and built, then install.h should be present
IS_DOT11SNMP := $(wildcard $(TGT_DIR)/h/wrn/wm/common/install.h)

# only build the current directory if WIND MANAGE SNMP is present
ifneq ($(IS_DOT11SNMP),)

C_SOURCE = $(wildcard *.c)


OBJS_wlanVxbEnd = $(C_SOURCE:.c=.o)

CFLAGS_LIB_wlanVxbEnd = -DVXBUS


ifeq ($(IP_PORT_VXWORKS),)
WR_IPCOM_NAME := vxworks
WR_IPCOM_VERSION := $(filter-out $(WR_IPCOM_NAME), $(subst -, ,$(WIND_PLATFORM)))
WR_IPCOM_VERSION := $(subst .,,$(WR_IPCOM_VERSION))
EXTRA_DEFINE += -DIP_PORT_VXWORKS=$(WR_IPCOM_VERSION)
endif

IPNET_ROOT_PATH := $(subst \,/,$(WRVX_COMPBASE))/$(subst \,/,$(COMP_IPNET2))
INCLUDE_CC += -I$(IPNET_ROOT_PATH)/ipnet2/include
INCLUDE_CC += -I$(IPNET_ROOT_PATH)/ipnet2/config
INCLUDE_CC += -I$(IPNET_ROOT_PATH)/ipcom/port/vxworks/include
INCLUDE_CC += -I$(IPNET_ROOT_PATH)/ipcom/port/vxworks/config
INCLUDE_CC += -I$(IPNET_ROOT_PATH)/ipcom/include
INCLUDE_CC += -I$(IPNET_ROOT_PATH)/ipcom/config


EXTRA_INCLUDE += -I$(IPNET_ROOT_PATH)/ipcrypto/openssl-3_0_13/include \
                 -I$(IPNET_ROOT_PATH)/ipcrypto/include \
                 -I$(IPNET_ROOT_PATH)/ipcrypto/config \
                 -I$(IPNET_ROOT_PATH)/ipssl2/include \
                 -I$(IPNET_ROOT_PATH)/ipssl2/config

include $(TGT_DIR)/h/make/rules.library

# if WIND MANAGE SNMP is not available, print a status message
else

default :
	@echo
	@echo SNMP component not available - this directory was not compiled
	@echo
man :

include $(TGT_DIR)/h/make/rules.library

endif
