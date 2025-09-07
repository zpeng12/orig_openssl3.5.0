#############################################################################
#			      IPCRYPTO_CONFIG.MK
#
#     Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto_config.mk,v $ $Revision: 1.19.10.1 $
#     $Source: /home/interpeak/CVSRoot/ipcrypto/gmake/ipcrypto_config.mk,v $
#     $Author: svc-cmnet $ $Date: 2013-03-13 07:45:19 $
#     $State: Exp $ $Locker:  $
#
#     INTERPEAK_COPYRIGHT_STRING
#
#############################################################################


#############################################################################
# CONFIGURATION
###########################################################################

ifeq ($(IPCRYPTO_OPENSSL_1_0_1),yes)
  IPCRYPTO_OPENSSL_ROOT = $(IPCRYPTO_ROOT)/openssl-1_0_1
  IPCFLAGS += -DIPCRYPTO_OPENSSL_1_0_1
else

  IPCRYPTO_OPENSSL_ROOT = $(IPCRYPTO_ROOT)/openssl-3_0_13
endif

ifeq ($(IPPORT),vxworks)
  include $(VSB_DIR)/h/config/auto.conf
endif

# These algorithms have an unclear patent situation, hence we remove them
IPCRYPTO_NO_MDC2 = yes
IPCRYPTO_NO_EC = yes
IPCRYPTO_NO_IDEA = yes
ifeq ($(_WRS_CONFIG_COMPONENT_IPCRYPTO_USE_FIPS_140_2),y)
  IPCRYPTO_USE_FIPS = yes
endif

ifneq ($(IPCRYPTO_OPENSSL_1_0_1),yes)
  # No asm support yet in openssl-1.0.1 port
  IPCRYPTO_USE_ASM = yes
endif

ifeq ($(IPCRYPTO_USE_ASM),yes)
  ifeq ($(IPARCH),pentium)
    ifneq ($(IPCOMPILER),diab)
      IPCRYPTO_USE_AES_ASM = yes
    endif
    IPCRYPTO_USE_BF_ASM = yes
    IPCRYPTO_USE_BN_ASM = yes
    IPCRYPTO_USE_CAST_ASM = yes
    IPCRYPTO_USE_DES_ASM = yes
    IPCRYPTO_USE_MD5_ASM = yes
    IPCRYPTO_USE_RC4_ASM = yes
    IPCRYPTO_USE_RMD_ASM = yes
    IPCRYPTO_USE_SHA_ASM = yes
  endif
  ifeq ($(IPARCH),pentium64)
    IPCRYPTO_USE_AES_ASM = yes
    ifeq ($(IPCOMPILER),gcc)   # Uses inline assembler; gcc specific
      IPCRYPTO_USE_BN_ASM = yes
    endif
    ifeq ($(IPCOMPILER),gnu)   # Uses inline assembler; gcc specific
      IPCRYPTO_USE_BN_ASM = yes
    endif
    IPCRYPTO_USE_MD5_ASM = yes
    IPCRYPTO_USE_RC4_ASM = yes
    IPCRYPTO_USE_SHA_ASM = yes
  endif
  ifeq ($(IPARCH),powerpc)
    IPCRYPTO_USE_BN_ASM = yes
  endif
else
  IPLIBDEFINE	+= -DOPENSSL_NO_ASM
endif

###########################################################################
# AUTO CONFIGURATION, DO NOT EDIT
###########################################################################

ifeq ($(IPCRYPTO_USE_BN_ASM),yes)
  ifeq ($(IPARCH),pentium)
    IPLIBDEFINE	+= -DOPENSSL_BN_ASM_PART_WORDS
  endif
endif

ifeq ($(IPCRYPTO_USE_AES_ASM),yes)
  IPLIBDEFINE	+= -DAES_ASM
endif

ifeq ($(IPCRYPTO_USE_SHA_ASM),yes)
  IPLIBDEFINE	+= -DSHA1_ASM
endif

ifeq ($(IPCRYPTO_USE_MD5_ASM),yes)
  IPLIBDEFINE	+= -DMD5_ASM
endif

ifeq ($(IPCRYPTO_USE_RMD_ASM),yes)
  IPLIBDEFINE	+= -DRMD160_ASM
endif

ifeq ($(IPBUILD),size)
IPCRYPTO_MINIMUM_FOOTPRINT = yes
endif

ifeq ($(IPPORT),itron)
  IPCRYPTO_NO_CONFIG = yes
else
  IPCRYPTO_NO_CONFIG = no
endif

ifeq ($(IPCRYPTO_MINIMUM_FOOTPRINT),yes)
  # Applications & test
  IPCRYPTO_NO_TEST = yes

  # Hash algorithms
  IPCRYPTO_NO_MD2 = yes
  IPCRYPTO_NO_MD4 = yes
  IPCRYPTO_NO_RIPEMD = yes

  # Symmetrical algorithms
  #IPCRYPTO_NO_AES = yes
  IPCRYPTO_NO_BF = yes
  IPCRYPTO_NO_CAST = yes
  IPCRYPTO_NO_RC2 = yes
  IPCRYPTO_NO_RC4 = yes

  # Asymmetrical algorithms
  # These algorithms are needed by IPIKE, IPSSH, IPSSL, IPWEBS
  #IPCRYPTO_NO_DSA = yes
  #IPCRYPTO_NO_DH = yes
  #ipwebs and ipsslproxy require RSA
  #IPCRYPTO_NO_RSA = yes

endif

ifeq ($(IPCRYPTO_USE_FIPS),yes)
  # Hash algorithms
  IPCRYPTO_NO_MD2 = yes
  IPCRYPTO_NO_RIPEMD = yes

  # Symmetrical algorithms
  IPCRYPTO_NO_BF = yes
  IPCRYPTO_NO_CAST = yes
  IPCRYPTO_NO_RC2 = yes
  IPCRYPTO_NO_RC4 = yes
endif


###########################################################################
# END OF IPCRYPTO_CONFIG.MK
###########################################################################
