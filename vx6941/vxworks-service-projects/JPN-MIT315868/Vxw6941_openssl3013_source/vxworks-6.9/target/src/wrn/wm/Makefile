#################################################################
#
# Makefile for building WMSNMP
#
# This makefile implements a simplified build system for building
# WindManageSNMP for Wind River Platforms.
# 
# Author: Tim Neale
# Date:   Aug. 30, 2002
#
# Revision History:
# Sep 23 2002	Changed name from makefile to Makefile
#		Added script for modifying ADDED_CFLAGS
# 16-Jul-2003   pservita reworked to avoid unecessary rebuilds
#
#################################################################

ifeq (,$(CPU))
CPU=none
endif

ifeq (,$(TOOL))
TOOL=gnu
endif



ifeq (,$(SNMPV3))
SNMPV3=OFF
endif

ifeq (,$(AGENTX))
AGENTX=OFF
endif

ifeq (,$(SNMP_CONFIG))
SNMP_CONFIG=NONE
endif

ifeq (,$(SNMP_IPV6))
SNMP_IPV6=OFF
endif
ifeq (,$(SNMP_IPV4))
SNMP_IPV4=OFF
endif

SNMP_VSTACK=OFF

ifeq (USER,$(SPACE))
SNMP_BUILD_TARGET=snmp_rtp
SNMP_CLEAN_TARGET=rclean_rtp
RTP_BUILD_MODE=RTP
AGENTX=ON
else
ifeq (user,$(SPACE))
SNMP_BUILD_TARGET=snmp_rtp
SNMP_CLEAN_TARGET=rclean_rtp
RTP_BUILD_MODE=RTP
AGENTX=ON
else
TGT_DIR = $(WIND_BASE)/target
include $(TGT_DIR)/h/make/defs.library
ifdef _WRS_CONFIG_COMPONENT_SNMP
SNMP_BUILD_TARGET=snmp
SNMP_CLEAN_TARGET=rclean_kernel

ifdef _WRS_CONFIG_FEATURE_IPNET_INET6
SNMP_IPV6=ON
SNMP_IPV4=ON
endif
ifdef _WRS_CONFIG_FEATURE_IPNET_INET6_ONLY
SNMP_IPV6=ON
SNMP_IPV4=OFF
endif
ifdef _WRS_CONFIG_FEATURE_IPNET_INET4_ONLY
SNMP_IPV6=OFF
SNMP_IPV4=ON
endif
ifdef _WRS_CONFIG_FEATURE_SNMP_V3
SNMPV3=ON
endif
ifdef _WRS_CONFIG_FEATURE_SNMP_AGENTX
AGENTX=ON
endif
else
#SNMP_BUILD_TARGET=rclean_kernel
#SNMP_CLEAN_TARGET=rclean_kernel
endif
BUILD_MODE=KERNEL
endif
endif

CONFIG_FILE=snmp.cfg


WIND_BASE := $(subst \,/,$(WIND_BASE))
TGT_DIR := $(WIND_BASE)/target


ifneq (,$(findstring solaris,$(WIND_HOST_TYPE)))
TOUCH       = touch
MAKMAK      = makmak
RUN_MAKMAK  = $(MAKMAK) $(CONFIG_FILE)
OUTPUT_CFG  = $(WIND_BASE)/target/src/wrn/wm/$(CONFIG_FILE)
RTP_OUTPUT_CFG  = $(WIND_BASE)/target/src/wrn/wm/$(CONFIG_FILE)
CFG_BUILD_TAG  = $(WIND_BASE)/target/src/wrn/wm/snmp_build.tag
else
ifneq (,$(findstring linux,$(WIND_HOST_TYPE)))
TOUCH       = touch
MAKMAK      = makmak
RUN_MAKMAK  = $(MAKMAK) $(CONFIG_FILE)
OUTPUT_CFG  = $(WIND_BASE)/target/src/wrn/wm/$(CONFIG_FILE)
RTP_OUTPUT_CFG  = $(WIND_BASE)/target/src/wrn/wm/$(CONFIG_FILE)
CFG_BUILD_TAG  = $(WIND_BASE)/target/src/wrn/wm/snmp_build.tag
else
ifneq (,$(findstring win32,$(WIND_HOST_TYPE)))
TOUCH       = echo.>
MAKMAK      = makmak
RUN_MAKMAK  = $(MAKMAK) $(CONFIG_FILE)
OUTPUT_CFG  = $(WIND_BASE)\target\src\wrn\wm\$(CONFIG_FILE)
RTP_OUTPUT_CFG  = $(WIND_BASE)\target\src\wrn\wm\$(CONFIG_FILE)
CFG_BUILD_TAG  = $(WIND_BASE)\target\src\wrn\wm\snmp_build.tag
endif
endif
endif

SNMP_TEMP_INCLUDES = ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/include ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/config ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/openssl-3_0_13/include ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssl2/openssl-3_0_13/include ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssl2/openssl-3_0_13/ssl ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/include ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/config ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/port/vxworks/include ADDED_CFLAGS+=-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/port/vxworks/config

default: $(SNMP_BUILD_TARGET)

snmp:snmp_build_and_install

snmp_tag_this_build:
	rm -f $(CFG_BUILD_TAG)
	cp $(OUTPUT_CFG) $(CFG_BUILD_TAG)

snmp_tag_this_rtp_build:
	rm -f $(CFG_BUILD_TAG)
	cp $(RTP_OUTPUT_CFG) $(CFG_BUILD_TAG)

snmp_makefiles:
	sh getcfg.sh $(CPU) $(TOOL) $(SNMPV3) $(AGENTX) $(CONFIG_FILE) $(SNMP_CONFIG) $(SNMP_IPV6) $(SNMP_VSTACK) $(BUILD_MODE) $(SNMP_IPV4)
	sh snmp_run_makmak.sh $(WIND_BASE) $(CPU) $(TOOL) $(OUTPUT_CFG) $(CFG_BUILD_TAG)
	sh chflags.sh
	rm -f $(CFG_BUILD_TAG)

snmp_build_and_install:
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) -C snmp all

ifndef _WRS_CONFIG_LP64
snmp_rtp: snmp_build_and_install_rtp
else
snmp_rtp:
endif

snmp_build_and_install_rtp:
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) SPACE=user -C snmp/engine
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) SPACE=user -C common/desreal
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) SPACE=user -C common/lib

rclean: $(SNMP_CLEAN_TARGET)

rclean_kernel:
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) -C snmp clean

rclean_rtp:
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) SPACE=user -C snmp/engine clean
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) SPACE=user -C common/desreal clean
	make CPU=$(CPU) TOOL=$(TOOL) $(SNMP_TEMP_INCLUDES) SPACE=user -C common/lib clean

man:  
	make -C snmp/engine man

