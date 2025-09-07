#############################################################################
#			      IPCRYPTO_APPS.MK
#
#     Document no: @(#) $Name: release6_9 $ $RCSfile: ipcrypto_openssl_apps_objs.mk,v $ $Revision: 1.3.2.2 $
#     $Source: /home/interpeak/CVSRoot/ipcrypto/openssl-1_0_1/gmake/ipcrypto_openssl_apps_objs.mk,v $
#     $Author: lchen3 $ $Date: 2015-01-30 02:26:15 $
#     $State: Exp $ $Locker:  $
#
#     INTERPEAK_COPYRIGHT_STRING
#
#############################################################################


#############################################################################
# OBJECTS
###########################################################################
IPINCLUDE	+= -I$(IPCRYPTO_ROOT)/src/
IPINCLUDE    += -I$(IPSSL_OPENSSL_ROOT)/ssl/
IPINCLUDE	+= -I$(IPCRYPTO_OPENSSL_ROOT)/
IPINCLUDE	+= -I$(IPCRYPTO_OPENSSL_ROOT)/include/
IPINCLUDE	+= -I$(IPCRYPTO_OPENSSL_ROOT)/crypto/bn/
IPINCLUDE	+= -I$(IPCRYPTO_OPENSSL_ROOT)/crypto/ec/curve448/
IPINCLUDE	+= -I$(IPCRYPTO_OPENSSL_ROOT)/crypto/x509/

# apps
#IPLIBOBJECTS   += apps.o

# apps-lib
IPLIBOBJECTS   += app_libctx.o app_params.o app_provider.o app_rand.o app_x509.o
IPLIBOBJECTS   += apps.o apps_ui.o cmp_mock_srv.o columns.o enginelib.o
IPLIBOBJECTS   += engine_loader.o fmt.o http_server.o names.o opt.o s_cb.o
IPLIBOBJECTS   += s_socket.o tlssrp_depr.o vms_decc_argv.o vms_term_sock.o

# helpers
IPLIBOBJECTS   += cmp_testlib.o handshake.o handshake_srp.o pkcs12.o 
IPLIBOBJECTS   += predefined_dhparams.o ssl_test_ctx.o ssltestlib.o

# testutil
IPLIBOBJECTS   += apps_shims.o basic_output.o cb.o driver.o fake_random.o
IPLIBOBJECTS   += format_output.o load.o main.o options.o output.o
IPLIBOBJECTS   += provider.o random.o stanza.o test_cleanup.o 
IPLIBOBJECTS   += test_options.o tests.o testutil_init.o




ifneq ($(IPPORT),las)
IPLIBOBJECTS   += verify.o asn1parse.o req.o dgst.o enc.o ca.o pkcs7.o crl2pkcs7.o crl.o
IPLIBOBJECTS   += x509.o  speed.o version.o nseq.o pkcs12.o pkcs8.o spkac.o smime.o 
IPLIBOBJECTS   += rand.o genpkey.o 

IPLIBOBJECTS   += cmd.o

ifneq ($(IPCRYPTO_NO_DH),yes)
IPLIBOBJECTS   += dhparam.o
endif
ifneq ($(IPCRYPTO_NO_ENGINE),yes)
IPLIBOBJECTS   += engine.o
endif
ifneq ($(IPCRYPTO_NO_MD5),yes)
IPLIBOBJECTS   += passwd.o
endif
ifneq ($(IPCRYPTO_NO_DSA),yes)
IPLIBOBJECTS   += dsa.o dsaparam.o gendsa.o
endif
ifneq ($(IPCRYPTO_NO_RSA),yes)
IPLIBOBJECTS   += rsa.o rsautl.o genrsa.o
endif
ifneq ($(IPCRYPTO_NO_OCSP),yes)
IPLIBOBJECTS   += ocsp.o
endif

#IPLIBOBJECTS	+= ssl_old_test.o testDriver.o bntest.o  \
IPLIBOBJECTS	+= ssl_old_test.o bntest.o  \
	destest.o sha_test.o \
	rand_test.o dhtest.o casttest.o \
	dsatest.o  exptest.o rsa_test.o \
	evp_test.o igetest.o 
IPLIBOBJECTS	+= rmdtest.o md5test.o wpackettest.o

#IPLIBOBJECTS	+= tabtest.o


IPLIBOBJECTS	+= 	test_test.o errtest.o context_internal_test.o  ctype_internal_test.o ext_internal_test.o keymgmt_internal_test.o 
IPLIBOBJECTS	+= 	provider_internal_test.o lhash_test.o localetest.o sparse_array_test.o stack_test.o exdatatest.o asn1_internal_test.o
IPLIBOBJECTS	+= 	asn1_dsa_internal_test.o bn_internal_test.o chacha_internal_test.o ffc_internal_test.o filterprov.o
IPLIBOBJECTS	+= 	mdc2_internal_test.o namemap_internal_test.o rsa_sp800_56b_test.o siphash_internal_test.o sm3_internal_test.o 
IPLIBOBJECTS	+= 	sm4_internal_test.o ssl_cert_table_internal_test.o x509_internal_test.o  modes_internal_test.o poly1305_internal_test.o
IPLIBOBJECTS	+= 	params_api_test.o property_test.o uitest.o asn1_decode_test.o asn1_encode_test.o asn1_stable_parse_test.o
IPLIBOBJECTS	+= 	asn1_string_table_test.o bio_callback_test.o bio_core_test.o bioprinttest.o conf_include_test.o endecode_test.o 
IPLIBOBJECTS	+= 	endecoder_legacy_test.o hexstr_test.o nodefltctxtest.o param_build_test.o params_test.o params_conversion_test.o

IPLIBOBJECTS	+= 	pem_read_depr_test.o pemtest.o provfetchtest.o provider_test.o provider_fallback_test.o provider_pkey_test.o
IPLIBOBJECTS	+= 	punycode_test.o upcallstest.o bftest.o casttest.o cmactest.o destest.o hmactest.o ideatest.o pbetest.o rand_test.o
IPLIBOBJECTS	+= 	rc2test.o rc4test.o rc5test.o algorithmid_test.o rdrand_sanitytest.o bntest.o exptest.o dhtest.o dsatest.o 
IPLIBOBJECTS	+= 	rsa_test.o sha_test.o crltest.o d2i_test.o pkcs7_test.o verify_extra_test.o aesgcmtest.o afalgtest.o defltfips_test.o
IPLIBOBJECTS	+= 	enginetest.o evp_test.o evp_extra_test.o evp_extra_test2.o evp_fetch_prov_test.o evp_kdf_test.o evp_libctx_test.o
IPLIBOBJECTS	+= 	evp_pkey_dparams_test.o evp_pkey_provided_test.o pbelutest.o pkey_meth_test.o pkey_meth_kdf_test.o
IPLIBOBJECTS	+= 	prov_config_test.o provider_status_test.o x509_check_cert_pkey_test.o x509_dup_cert_test.o x509_time_test.o
IPLIBOBJECTS	+= 	bio_prefix_text.o bio_readbuffer_test.o cmp_asn_test.o cmp_client_test.o cmp_ctx_test.o ssl_strtoimax.o fake_rsaprov.o

#IPLIBOBJECTS	+= 	cmp_hdr_test.o cmp_vfy_test.o gmdifftest.o				struct tm  update time in reference to adjtime.c

IPLIBOBJECTS	+= 	cmp_msg_test.o cmp_protect_test.o cmp_server_test.o cmp_status_test.o ossl_store_test.o asynciotest.o
IPLIBOBJECTS	+= 	bad_dtls_test.o clienthellotest.o packettest.o recordlentest.o servername_test.o verify_extra_test.o wpackettest.o
IPLIBOBJECTS	+= 	ssl_ctx_test.o http_test.o cipherbytes_test.o cipherlist_test.o ciphername_test.o cmsapitest.o ct_test.o danetest.o 
IPLIBOBJECTS	+= 	dtlstest.o dtls_mtu_test.o dtlsv1listentest.o ocspapitest.o pkcs12_format_test.o ssl_test_ctx_test.o 
IPLIBOBJECTS	+= 	ssl_old_test.o  ssl_test.o sslcorrupttest.o x509aux.o cmp_client_test.o asn1_time_test.o asynctest.o bio_enc_test.o 
IPLIBOBJECTS	+= 	bio_memleak_test.o constant_time_test.o fatalerrtest.o  igetest.o memleaktest.o secmemtest.o shlibloadtest.o
IPLIBOBJECTS	+= 	srptest.o sslapitest.o sslbuffertest.o sysdefaulttest.o threadstest.o tls13ccstest.o tls13encryptiontest.o tls13secretstest.o
IPLIBOBJECTS	+= 	trace_api_test.o v3nametest.o ecstresstest.o tls_provider.o


#IPLIBOBJECTS	+= 	curve448_internal_test.o	#ec?


IPLIBOBJECTS	+= provider_test.o  ssl_ctx_test.o sslapitest.o ssl_test.o p_test.o

IPLIBOBJECTS	+= evp_extra_test.o v3nametest.o \
	constant_time_test.o

	
ifneq ($(IPCRYPTO_NO_RC2),yes)
IPLIBOBJECTS	+= rc2test.o
endif
ifneq ($(IPCRYPTO_NO_RC4),yes)
IPLIBOBJECTS	+= rc4test.o
endif
ifneq ($(IPCRYPTO_NO_MD2),yes)
#IPLIBOBJECTS	+=  md2test.o
endif
ifneq ($(IPCRYPTO_NO_MD4),yes)
#IPLIBOBJECTS	+=  md4test.o
endif
ifneq ($(IPCRYPTO_NO_MD5),yes)
#IPLIBOBJECTS	+=  md5test.o
endif
ifneq ($(IPCRYPTO_NO_MDC2),yes)
IPLIBOBJECTS	+=  mdc2test.o
endif
ifneq ($(IPCRYPTO_NO_SHA),yes)
IPLIBOBJECTS	+=  sha_test.o
ifeq ($(IPCRYPTO_OPENSSL_1_0_2),yes)
IPLIBOBJECTS	+=  sha256t.o
endif
#IPLIBOBJECTS	+=  sha512t.o
endif
ifneq ($(IPCRYPTO_NO_HMAC),yes)
IPLIBOBJECTS	+=  hmactest.o
endif
ifneq ($(IPCRYPTO_NO_BF),yes)
IPLIBOBJECTS	+=  bftest.o
endif
ifneq ($(IPCRYPTO_NO_EC),yes)
IPLIBOBJECTS	+= ectest.o
IPLIBOBJECTS	+= ecdhtest.o
IPLIBOBJECTS	+= ecdsatest.o
endif
ifneq ($(IPCRYPTO_NO_ENGINE),yes)
IPLIBOBJECTS	+= enginetest.o
endif

ifneq ($(IPCRYPTO_NO_SRP),yes)
#IPLIBOBJECTS	+= srptest.o
endif

ifneq ($(IPCRYPTO_NO_WP),yes)
#IPLIBOBJECTS	+= wp_test.o
endif


endif



#############################################################################
# SOURCE
###########################################################################

IPSRCDIRS 	+= $(IPCRYPTO_ROOT)/src/testutil
IPSRCDIRS 	+= $(IPCRYPTO_ROOT)/src/helpers
IPSRCDIRS 	+= $(IPCRYPTO_ROOT)/src/helpers

IPSRCDIRS 	+= $(IPCRYPTO_OPENSSL_ROOT)/apps
IPSRCDIRS 	+= $(IPCRYPTO_OPENSSL_ROOT)/apps/lib
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/bf
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/bn
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/cast
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/des
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/dh
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/dsa
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ec
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ecdh
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ecdsa
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/evp
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/engine
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/hmac
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md2
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md4
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md5
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/mdc2
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rand
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rc2
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rc4
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ripemd
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rsa
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/sha
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/sha
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/x509v3
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ffc
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/

#############################################################################
# BINARIES
#############################################################################

ifeq ($(IPPORT),las)
# Path to binaries
IPCMDDIR 	:= $(IPOBJDIR)/bin

# List of shell commands to build
IPCRYPTOSHELLCMDS	= evp_test speed
_IPCRYPTOSHELLCMDS	= $(addprefix $(IPCMDDIR)/,$(IPCRYPTOSHELLCMDS))

bin:	$(_IPCRYPTOSHELLCMDS)

$(IPOBJDIR)/ipcrypto_apps/%.o:	$(IPCRYPTO_OPENSSL_ROOT)/apps/%.o
	@$(IPECHO) "+++ Compiling IPCRYPTO shell command $<"
	$(IPVERB)$(IPCC) -DMAIN=ipcom_cmd_entry_point $(IPLIBINCLUDE) $(IPCFLAGS) -o $@ $<

$(IPOBJDIR)/ipcrypto_apps/evp_test.o:	$(IPCRYPTO_OPENSSL_ROOT)/crypto/evp/evp_test.o
	@$(IPECHO) "+++ Compiling IPCRYPTO shell command $<"
	$(IPVERB)$(IPCC) -DMAIN=ipcom_cmd_entry_point $(IPLIBINCLUDE) $(IPCFLAGS) -o $@ $<

$(IPCMDDIR)/speed:	$(IPOBJDIR)/ipcrypto_apps/speed.o $(IPOBJDIR)/ipcom_shell_cmd_stub.o
	@$(IPECHO) "+++ Linking IPCRYPTO shell command $@"
	$(IPVERB)$(IPLD) -o $@ $(IPLDFLAGS) $^ $(IPLIBS) $(IPLIBS) $(IPLIBS) $(IPLASTLIBS)


$(IPCMDDIR)/evp_test:	$(IPOBJDIR)/ipcrypto_apps/evp_test.o $(IPOBJDIR)/ipcom_shell_cmd_stub.o
	@$(IPECHO) "+++ Linking IPCRYPTO shell command $@"
	$(IPVERB)$(IPLD) -o $@ $(IPLDFLAGS) $^ $(IPLIBS) $(IPLIBS) $(IPLIBS) $(IPLASTLIBS)


endif

###########################################################################
# END OF IPCRYPTO_APPS.MK
###########################################################################

