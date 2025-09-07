#############################################################################
#			      IPSSL.MK
#
#     Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipssl_openssl_objs.mk,v $ $Revision: 1.1.12.1 $
#     $Source: /home/interpeak/CVSRoot/ipssl2/openssl-0_9_8/gmake/ipssl_openssl_objs.mk,v $
#     $Author: jli7 $ $Date: 2014-03-20 07:50:19 $
#     $State: Exp $ $Locker:  $
#
#     INTERPEAK_COPYRIGHT_STRING
#
#############################################################################


#############################################################################
# INCLUDE
###########################################################################

IPINCLUDE += -I$(IPSSL_OPENSSL_ROOT)/include

IPLIBINCLUDE += -I$(IPXINC_ROOT)/include


#############################################################################
# OBJECTS
###########################################################################

IPLIBOBJECTS += bio_ssl.o
IPLIBOBJECTS += d1_lib.o
IPLIBOBJECTS += d1_msg.o
IPLIBOBJECTS += d1_srtp.o
IPLIBOBJECTS += ktls.o
IPLIBOBJECTS += methods.o
IPLIBOBJECTS += pqueue.o
IPLIBOBJECTS += s3_cbc.o
IPLIBOBJECTS += s3_enc.o
IPLIBOBJECTS += s3_lib.o
IPLIBOBJECTS += s3_msg.o
IPLIBOBJECTS += ssl_asn1.o
IPLIBOBJECTS += ssl_cert.o
IPLIBOBJECTS += ssl_ciph.o
IPLIBOBJECTS += ssl_conf.o
IPLIBOBJECTS += ssl_err.o
IPLIBOBJECTS += ssl_err_legacy.o
IPLIBOBJECTS += ssl_init.o
IPLIBOBJECTS += ssl_lib.o
IPLIBOBJECTS += ssl_mcnf.o
IPLIBOBJECTS += ssl_rsa.o
IPLIBOBJECTS += ssl_rsa_legacy.o
IPLIBOBJECTS += ssl_sess.o
IPLIBOBJECTS += ssl_stat.o
IPLIBOBJECTS += ssl_txt.o
IPLIBOBJECTS += ssl_utst.o
IPLIBOBJECTS += t1_enc.o
IPLIBOBJECTS += t1_lib.o
IPLIBOBJECTS += t1_trce.o
IPLIBOBJECTS += tls13_enc.o
IPLIBOBJECTS += tls_depr.o
IPLIBOBJECTS += tls_srp.o

#ssl2-ssl-record
IPLIBOBJECTS += dtls1_bitmap.o
IPLIBOBJECTS += rec_layer_d1.o
IPLIBOBJECTS += rec_layer_s3.o
IPLIBOBJECTS += ssl3_buffer.o
IPLIBOBJECTS += ssl3_record.o
IPLIBOBJECTS += ssl3_record_tls13.o
IPLIBOBJECTS += tls_pad.o

#ssl2-ssl-statem
IPLIBOBJECTS += extensions.o
IPLIBOBJECTS += extensions_clnt.o
IPLIBOBJECTS += extensions_cust.o
IPLIBOBJECTS += extensions_srvr.o
IPLIBOBJECTS += statem.o
IPLIBOBJECTS += statem_clnt.o
IPLIBOBJECTS += statem_dtls.o
IPLIBOBJECTS += statem_lib.o
IPLIBOBJECTS += statem_srvr.o


# Shell commands
ifneq ($(IPPORT),itron)
IPLIBOBJECTS += s_client.o
IPLIBOBJECTS += s_server.o
endif

IPLIBOBJECTS += s_time.o
IPLIBOBJECTS += ciphers.o
IPLIBOBJECTS += errstr.o

# Test shell commands



#############################################################################
# SOURCE
###########################################################################

IPSRCDIRS += $(IPSSL_OPENSSL_ROOT)/apps
IPSRCDIRS += $(IPSSL_OPENSSL_ROOT)/ssl
IPSRCDIRS += $(IPSSL_OPENSSL_ROOT)/ssl/record
IPSRCDIRS += $(IPSSL_OPENSSL_ROOT)/ssl/statem


#############################################################################
# LIB
###########################################################################

IPLIBS += $(IPLIBROOT)/libipssl.a


###########################################################################
# END OF IPSSL2.MK
###########################################################################
