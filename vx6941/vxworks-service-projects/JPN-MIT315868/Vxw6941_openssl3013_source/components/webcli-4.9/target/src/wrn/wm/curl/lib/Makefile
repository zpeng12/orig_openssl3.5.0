# Makefile - makefile for src/wrn/wmw
#
# Copyright (c) 2002-2007, 2009, 2011-2013 Wind River Systems, Inc.
#
# modification history
# --------------------
# 01h,18apr13,r_w  eliminate warning, defect WIND00413440
# 01g,24jul12,r_w  fix undefined SSL symbols issue on RTP space(defect WIND00365069)
# 01f,15dec11,r_w  fix icc build error(defect WIND00251394)
# 01e,02nov09,mdk  fix comment
# 01d,30oct09,m_z  use VSB lib path for default
#                   (WIND00188837)
# 01c,17oct07,pee  using ipcom rules.
# 01b,05sep07,msa  Update with new C filenames.
# 01a,26sep06,msa  Update this so it is the primary build point.
#
# DESCRIPTION
# This file contains the makefile rules for building the wmw library
#
#*/

WIND_HOME := $(subst \,/,$(WIND_HOME))
WIND_BASE := $(subst \,/,$(WIND_BASE))
WIND_USR  := $(subst \,/,$(WIND_USR))

ifeq ($(SPACE),)
  SPACE = kernel
endif

ifeq ($(SPACE),kernel)
  TGT_DIR       = $(WIND_BASE)/target
endif

ifeq ($(SPACE),user)
  TGT_DIR       = $(WIND_BASE)/target/usr
endif

LIB_BASE_NAME = curl


# Using CURL_BASE works whether or not we are under WIND_BASE.

CURL_BASE = ../../../../../..

ifeq ($(SPACE),kernel)
CURL_INCLUDE_DIRS= 	-I$(WIND_BASE)/target/h \
			-I$(WIND_BASE)/target/h/wrn \
			-I$(WIND_BASE)/target/h/wrn/coreip
endif

ifeq ($(SPACE),user)
CURL_INCLUDE_DIRS= 	 	-I$(WIND_BASE)/target/usr/h \
			-I$(WIND_BASE)/target/usr/h/wrn \
			-I$(WIND_BASE)/target/usr/h/wrn/coreip
endif

ifeq ($(findstring diab,$(TOOL)),diab)
CURL_INCLUDE_DIRS += -I$(CURL_BASE)/target/h/wrn/wm/curl
else
CURL_INCLUDE_DIRS += -idirafter $(CURL_BASE)/target/h/wrn/wm/curl
endif

CURL_INCLUDE_DIRS += 	-I$(CURL_BASE)/target/h/wrn/wm \
			-I$(CURL_BASE)/target/src/wrn/wm/curl/lib \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/include \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/config \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcrypto/openssl-3_0_13/include \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssl2/openssl-3_0_13/ssl \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipssl2/openssl-3_0_13/include \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/include \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/config \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/port/vxworks/include \
			-I$(WRVX_COMPBASE)/$(COMP_IPNET2)/ipcom/port/vxworks/config


WRN_DEFINITIONS= -D__VxWORKS__ -D__BIG_ENUMS__ -DWRN_PD_CODE

CURL_DEFINITIONS=

# Curl definitions for turning components on and off ...
# Curl definitions for supoorted features in vxWorks...
#CURL_DEFINITIONS+= -DCURL_DISABLE_COOKIES
#CURL_DEFINITIONS+= -DCURL_DISABLE_HTTP
#CURL_DEFINITIONS+= -DCURL_DISABLE_HTTPS
#CURL_DEFINITIONS+= -DCURL_DISABLE_VERBOSE_STRINGS
# Curl definitions for unsupported feaures which are disabled by default...
CURL_DEFINITIONS+= -DCURL_DISABLE_CRYPTO_AUTH
CURL_DEFINITIONS+= -DCURL_DISABLE_DICT
CURL_DEFINITIONS+= -DCURL_DISABLE_FILE
CURL_DEFINITIONS+= -DCURL_DISABLE_FTP
CURL_DEFINITIONS+= -DCURL_DISABLE_LDAP
CURL_DEFINITIONS+= -DCURL_DISABLE_TELNET
CURL_DEFINITIONS+= -DCURL_DISABLE_TFTP

#Curl definitions for defining the capabilities of the OS
CURL_DEFINITIONS+= -DHAVE_CONFIG_H

ifeq ($(SPACE),user)
CURL_DEFINITIONS+= -DCURL_DISABLE_HTTPS
else
CURL_DEFINITIONS+= -UCURL_DISABLE_HTTPS
endif

#SDA defaults to disabled on some architectures and breaks perfectly functioning builds
SDA_DISABLE=TRUE

ifeq ($(DEBUG),YES)
override EXTRA_DEFINE += -g -O0 -D__VxDEBUG__ -D__WRN_DEF_DEBUG__ $(WRN_DEFINITIONS) $(CURL_DEFINITIONS) $(CURL_INCLUDE_DIRS)
else
override EXTRA_DEFINE += $(WRN_DEFINITIONS) $(CURL_DEFINITIONS) $(CURL_INCLUDE_DIRS)
endif

SRC_FILES =     libcurl_base64.c \
		libcurl_connect.c \
		libcurl_content_encoding.c \
		libcurl_cookie.c \
		libcurl_dict.c \
		libcurl_easy.c \
		libcurl_escape.c \
		libcurl_file.c \
		libcurl_formdata.c \
		libcurl_ftp.c \
		libcurl_getenv.c \
		libcurl_getinfo.c \
		libcurl_gtls.c \
		libcurl_hash.c \
		libcurl_hostares.c \
		libcurl_hostasyn.c \
		libcurl_hostip4.c \
		libcurl_hostip6.c \
		libcurl_hostip.c \
		libcurl_hostsyn.c \
		libcurl_hostthre.c \
		libcurl_http.c \
		libcurl_http_chunks.c \
		libcurl_http_digest.c \
		libcurl_http_negotiate.c \
		libcurl_http_ntlm.c \
		libcurl_if2ip.c \
		libcurl_inet_ntop.c \
		libcurl_inet_pton.c \
		libcurl_krb4.c \
		libcurl_ldap.c \
		libcurl_llist.c \
		libcurl_md5.c \
		libcurl_mprintf.c \
		libcurl_multi.c \
		libcurl_netrc.c \
		libcurl_parsedate.c \
		libcurl_progress.c \
		libcurl_security.c \
		libcurl_select.c \
		libcurl_sendf.c \
		libcurl_share.c \
		libcurl_speedcheck.c \
		libcurl_sslgen.c \
		libcurl_ssluse.c \
		libcurl_strequal.c \
		libcurl_strerror.c \
		libcurl_strtok.c \
		libcurl_strtoofft.c \
		libcurl_telnet.c \
		libcurl_tftp.c \
		libcurl_timeval.c \
		libcurl_transfer.c \
		libcurl_url.c \
		libcurl_version.c
		
#		libcurl_memorydebug.c		

OBJS= $(SRC_FILES:%c=%o)

DOC_FILES= $(SRC_FILES)

ifeq ($(SPACE),user)
include $(TGT_DIR)/make/defs.default
include $(WRVX_COMPBASE)/$(COMP_IPNET2)/osconfig/vxworks/make/defs.ipcom
include $(TGT_DIR)/make/rules.library
include $(WRVX_COMPBASE)/$(COMP_IPNET2)/osconfig/vxworks/make/rules.ipcom
else
include $(TGT_DIR)/h/make/defs.library
include $(WRVX_COMPBASE)/$(COMP_IPNET2)/osconfig/vxworks/make/defs.ipcom
include $(TGT_DIR)/h/make/rules.library
include $(WRVX_COMPBASE)/$(COMP_IPNET2)/osconfig/vxworks/make/rules.ipcom
endif

#ifeq ($(SPACE),user)
#rclean:
#	rm -rf $(LIB_ROOT)/$(VX_CPU_FAMILY)/$(CPU)/$(TOOL_COMMON_DIR)/objcurl
#	rm -rf $(LIB_ROOT)/$(VX_CPU_FAMILY)/$(CPU)/$(TOOL_COMMON_DIR)/libcurl.a
#endif
