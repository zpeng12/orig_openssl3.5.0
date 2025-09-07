#############################################################################
#			INTERPEAK DMAKE MAKEFILE
#
#     Document no: @(#) $Name: release6_9 $ $RCSfile: ipcrypto_openssl_objs.mk,v $ $Revision: 1.6.2.2 $
#     $Source: /home/interpeak/CVSRoot/ipcrypto/openssl-1_0_1/gmake/ipcrypto_openssl_objs.mk,v $
#     $Author: lchen3 $
#     $State: Exp $ $Locker:  $
#
#     INTERPEAK_COPYRIGHT_STRING
#     Design and implementation by Roger Boden <roger.boden@windriver.oom>
#############################################################################

#############################################################################
# DESCRIPTION
#############################################################################
# IPPRODUCT dmake build description.


#############################################################################
# PATHS
#############################################################################

# object root
#IPPRODUCT_OBJROOT *= $(IPOBJDIR)$/ipproduct


#############################################################################
# IPDEFINE
#############################################################################

#IPDEFINE += IPPRODUCT


#############################################################################
# IPINCLUDE
#############################################################################

IPINCLUDE 	+= -I$(IPCRYPTO_OPENSSL_ROOT)/include
IPINCLUDE	+= -I$(IPCRYPTO_OPENSSL_ROOT)/crypto
IPINCLUDE	+= -I$(IPCRYPTO_OPENSSL_ROOT) # TODO: added for crypto.h. Move this file instead?
IPINCLUDE 	+= -I$(IPCRYPTO_OPENSSL_ROOT)/include/openssl
IPINCLUDE 	+= -I$(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/include

IPLIBINCLUDE 	+= -I$(IPXINC_ROOT)/include

ifeq ($(OPENSSL102_USE_ASM_ITL),yes)
ifdef _WRS_CONFIG_ILP32
IPLIBOBJECTS += x86cpuid.o
endif
ifdef _WRS_CONFIG_LP64
IPLIBOBJECTS += x86_64cpuid.o
endif
endif



ifeq ($(OPENSSL102_USE_ASM_PPC),yes)
IPLIBOBJECTS += ppccap.o
IPLIBOBJECTS += ppccpuid.o
endif


IPLIBOBJECTS += init.o
IPLIBOBJECTS += trace.o

#crypto-aes
IPLIBOBJECTS += aes_cbc.o
IPLIBOBJECTS += aes_cfb.o
ifneq ($(OPENSSL102_USE_ASM_ARM),yes)
IPLIBOBJECTS += aes_core.o
endif
IPLIBOBJECTS += aes_ecb.o
IPLIBOBJECTS += aes_ige.o
IPLIBOBJECTS += aes_misc.o
IPLIBOBJECTS += aes_ofb.o
IPLIBOBJECTS += aes_wrap.o
IPLIBOBJECTS += aes_x86core.o
ifeq ($(OPENSSL102_USE_ASM_ARM),yes)
IPLIBOBJECTS +=  aes-armv4.o
IPLIBOBJECTS +=  aesv8-armx.o
IPLIBOBJECTS +=  bsaes-armv7.o
endif
ifeq ($(OPENSSL102_USE_ASM_PPC),yes)
IPLIBOBJECTS +=  aes-ppc.o
endif

#crypto-aria
IPLIBOBJECTS += aria.o

#crypto-asn1
IPLIBOBJECTS += a_bitstr.o
IPLIBOBJECTS += a_d2i_fp.o
IPLIBOBJECTS += a_digest.o
IPLIBOBJECTS += a_dup.o
IPLIBOBJECTS += a_gentm.o
IPLIBOBJECTS += a_i2d_fp.o
IPLIBOBJECTS += a_int.o
IPLIBOBJECTS += a_mbstr.o
IPLIBOBJECTS += a_object.o
IPLIBOBJECTS += a_octet.o
IPLIBOBJECTS += a_print.o
IPLIBOBJECTS += a_sign.o
IPLIBOBJECTS += a_strex.o
IPLIBOBJECTS += a_strnid.o
IPLIBOBJECTS += a_time.o 
IPLIBOBJECTS += a_type.o
IPLIBOBJECTS += a_utctm.o
IPLIBOBJECTS += a_utf8.o
IPLIBOBJECTS += a_verify.o
IPLIBOBJECTS += ameth_lib.o
IPLIBOBJECTS += asn1_err.o
IPLIBOBJECTS += asn1_gen.o
IPLIBOBJECTS += asn1_item_list.o
IPLIBOBJECTS += asn1_lib.o
IPLIBOBJECTS += asn1_parse.o
IPLIBOBJECTS += asn_mime.o
IPLIBOBJECTS += asn_moid.o
IPLIBOBJECTS += asn_mstbl.o
IPLIBOBJECTS += asn_pack.o
IPLIBOBJECTS += bio_asn1.o
IPLIBOBJECTS += bio_ndef.o
IPLIBOBJECTS += d2i_param.o
IPLIBOBJECTS += d2i_pr.o
IPLIBOBJECTS += d2i_pu.o
IPLIBOBJECTS += evp_asn1.o
IPLIBOBJECTS += f_int.o
IPLIBOBJECTS += f_string.o
IPLIBOBJECTS += i2d_evp.o
IPLIBOBJECTS += n_pkey.o
IPLIBOBJECTS += nsseq.o
IPLIBOBJECTS += p5_pbe.o
IPLIBOBJECTS += p5_pbev2.o
IPLIBOBJECTS += p5_scrypt.o
IPLIBOBJECTS += p8_pkey.o
IPLIBOBJECTS += t_bitst.o
IPLIBOBJECTS += t_pkey.o
IPLIBOBJECTS += t_spki.o
IPLIBOBJECTS += tasn_dec.o
IPLIBOBJECTS += tasn_enc.o
IPLIBOBJECTS += tasn_fre.o
IPLIBOBJECTS += tasn_new.o
IPLIBOBJECTS += tasn_prn.o
IPLIBOBJECTS += tasn_scn.o
IPLIBOBJECTS += tasn_typ.o
IPLIBOBJECTS += tasn_utl.o
IPLIBOBJECTS += x_algor.o
IPLIBOBJECTS += x_bignum.o
IPLIBOBJECTS += x_info.o 
IPLIBOBJECTS += x_int64.o
IPLIBOBJECTS += x_long.o
IPLIBOBJECTS += x_pkey.o
IPLIBOBJECTS += x_sig.o
IPLIBOBJECTS += x_spki.o
IPLIBOBJECTS += x_val.o


#crypto-async
IPLIBOBJECTS += async.o
IPLIBOBJECTS += async_err.o
IPLIBOBJECTS += async_wait.o
IPLIBOBJECTS += async_null.o
IPLIBOBJECTS += async_posix.o


#crypto-bf
ifneq ($(IPCRYPTO_NO_BF),yes)
IPLIBOBJECTS += bf_cfb64.o
IPLIBOBJECTS += bf_ecb.o
IPLIBOBJECTS += bf_ofb64.o
IPLIBOBJECTS += bf_skey.o
IPLIBOBJECTS += e_bf.o 		#evp

ifneq ($(IPCRYPTO_USE_BF_ASM),yes)
IPLIBOBJECTS += bf_enc.o
endif

endif

#crypto-bio
IPLIBOBJECTS += bf_buff.o bf_lbuf.o bf_nbio.o bf_null.o bf_prefix.o bf_readbuff.o
IPLIBOBJECTS += bio_addr.o bio_cb.o bio_dump.o bio_err.o bio_lib.o bio_meth.o bio_print.o bio_sock2.o bio_sock.o
IPLIBOBJECTS += bss_acpt.o bss_bio.o bss_conn.o bss_core.o bss_dgram.o bss_fd.o bss_file.o
IPLIBOBJECTS += bss_log.o bss_mem.o bss_null.o bss_sock.o ossl_core_bio.o

#crypto-bn
IPLIBOBJECTS += bn_add.o bn_asm.o bn_blind.o bn_const.o bn_conv.o bn_ctx.o bn_depr.o
IPLIBOBJECTS += bn_dh.o		#ossl_bignum_ffdhe2048_p
IPLIBOBJECTS += bn_div.o bn_err.o bn_exp2.o bn_exp.o bn_gcd.o bn_gf2m.o bn_intern.o
IPLIBOBJECTS += bn_kron.o bn_lib.o bn_mod.o bn_mont.o bn_mpi.o bn_mul.o bn_nist.o
IPLIBOBJECTS += bn_ppc.o bn_prime.o bn_print.o bn_rand.o bn_recp.o bn_srp.o
IPLIBOBJECTS += bn_rsa_fips186_4.o bn_shift.o bn_sparc.o bn_sqr.o bn_sqrt.o bn_word.o
IPLIBOBJECTS += rsaz_exp.o rsaz_exp_x2.o bn_err.o bn_const.o bn_exp.o bn_blind.o
IPLIBOBJECTS += bn_add.o bn_rand.o bn_nist.o bn_lib.o bn_prime.o bn_recp.o bn_mul.o
IPLIBOBJECTS += bn_mpi.o bn_word.o bn_print.o bn_x931p.o
ifneq ($(OPENSSL102_USE_ASM_ITL),yes)
IPLIBOBJECTS += bn_asm.o
endif

#crypto-buffer
IPLIBOBJECTS += buffer.o buf_err.o

#crypto-camellia
IPLIBOBJECTS += camellia.o
IPLIBOBJECTS += cmll_cbc.o
IPLIBOBJECTS += cmll_cfb.o
IPLIBOBJECTS += cmll_ctr.o
IPLIBOBJECTS += cmll_ecb.o
IPLIBOBJECTS += cmll_misc.o
IPLIBOBJECTS += cmll_ofb.o
 
#crypto-cast
ifneq ($(IPCRYPTO_NO_CAST),yes)
IPLIBOBJECTS += c_cfb64.o c_enc.o c_ecb.o c_ofb64.o c_skey.o
IPLIBOBJECTS += e_cast.o #evp
endif

#crypto-chacha
IPLIBOBJECTS += chacha_enc.o

#  crypto-cmac 
IPLIBOBJECTS += cmac.o

# crypto-cmp
IPLIBOBJECTS += cmp_asn.o cmp_client.o cmp_ctx.o cmp_err.o cmp_hdr.o cmp_http.o
IPLIBOBJECTS += cmp_msg.o cmp_protect.o cmp_server.o cmp_status.o cmp_util.o cmp_vfy.o

# crypto-cms
IPLIBOBJECTS += cms_asn1.o cms_att.o cms_cd.o cms_dd.o cms_dh.o cms_enc.o cms_env.o cms_err.o
IPLIBOBJECTS += cms_ess.o cms_io.o cms_kari.o cms_lib.o cms_pwri.o cms_rsa.o cms_sd.o cms_smime.o

#crypto-comp
IPLIBOBJECTS += c_zlib.o comp_err.o comp_lib.o

# crypto-conf
IPLIBOBJECTS += conf_api.o conf_def.o conf_err.o conf_lib.o conf_mall.o conf_mod.o
IPLIBOBJECTS += conf_sap.o conf_ssl.o

#crypo-crmf
IPLIBOBJECTS += crmf_asn.o crmf_err.o crmf_lib.o crmf_pbm.o

#crypto-ct
IPLIBOBJECTS += ct_b64.o ct_err.o ct_log.o ct_oct.o ct_policy.o ct_prn.o ct_sct.o
IPLIBOBJECTS += ct_sct_ctx.o ct_vfy.o ct_x509v3.o

#crypto-des
IPLIBOBJECTS += cbc_cksm.o cbc_enc.o cfb64ede.o cfb64enc.o cfb_enc.o des_enc.o
IPLIBOBJECTS += ecb3_enc.o ecb_enc.o fcrypt.o fcrypt_b.o ncbc_enc.o ofb64ede.o
IPLIBOBJECTS += ofb64enc.o ofb_enc.o pcbc_enc.o qud_cksm.o rand_key.o set_key.o
IPLIBOBJECTS += str2key.o xcbc_enc.o


#crypto-dh
IPLIBOBJECTS += dh_ameth.o dh_asn1.o dh_backend.o dh_check.o dh_depr.o
IPLIBOBJECTS += dh_err.o dh_gen.o dh_group_params.o dh_kdf.o
IPLIBOBJECTS += dh_key.o dh_lib.o dh_meth.o dh_pmeth.o dh_prn.o dh_rfc5114.o


#crypto-dsa
IPLIBOBJECTS += dsa_ameth.o dsa_asn1.o dsa_backend.o dsa_check.o dsa_depr.o dsa_err.o
IPLIBOBJECTS += dsa_gen.o dsa_key.o dsa_lib.o dsa_meth.o dsa_ossl.o dsa_pmeth.o
IPLIBOBJECTS += dsa_prn.o dsa_sign.o dsa_vrf.o

#crypto-dso
IPLIBOBJECTS += dso_dl.o dso_dlfcn.o dso_err.o dso_lib.o dso_openssl.o dso_vms.o

#crypto-encoder-decoder
IPLIBOBJECTS += decoder_err.o decoder_lib.o decoder_meth.o decoder_pkey.o
IPLIBOBJECTS += encoder_err.o encoder_lib.o encoder_meth.o encoder_pkey.o

#crypto-engine
IPLIBOBJECTS += eng_all.o eng_cnf.o eng_ctrl.o eng_dyn.o eng_err.o eng_fat.o eng_init.o
IPLIBOBJECTS += eng_lib.o eng_list.o eng_openssl.o eng_pkey.o eng_rdrand.o eng_table.o
IPLIBOBJECTS += tb_asnmth.o tb_cipher.o tb_dh.o tb_digest.o tb_dsa.o tb_pkmeth.o
IPLIBOBJECTS += tb_rand.o tb_rsa.o
IPLIBOBJECTS += tb_eckey.o			#default ec key

#crypto-err
IPLIBOBJECTS += err.o err_all.o err_all_legacy.o err_blocks.o err_prn.o

#crypo-ess
IPLIBOBJECTS += ess_asn1.o ess_lib.o ess_err.o

# evp
IPLIBOBJECTS += asymcipher.o bio_b64.o bio_enc.o bio_md.o bio_ok.o c_alld.o c_allc.o
IPLIBOBJECTS += cmeth_lib.o ctrl_params_translate.o dh_ctrl.o dh_support.o digest.o
IPLIBOBJECTS += dsa_ctrl.o e_aes.o e_aes_cbc_hmac_sha1.o e_aes_cbc_hmac_sha256.o
IPLIBOBJECTS += e_aria.o e_bf.o e_camellia.o e_cast.o e_chacha20_poly1305.o e_des.o
IPLIBOBJECTS += e_des3.o e_idea.o e_null.o e_old.o e_rc2.o e_rc4.o e_rc4_hmac_md5.o
IPLIBOBJECTS += e_rc5.o e_seed.o e_sm4.o e_xcbc_d.o encode.o evp_cnf.o evp_enc.o
IPLIBOBJECTS += evp_err.o  evp_fetch.o evp_key.o evp_lib.o evp_pbe.o evp_pkey.o
IPLIBOBJECTS += evp_rand.o evp_utils.o exchange.o
IPLIBOBJECTS += kdf_lib.o kdf_meth.o kem.o keymgmt_lib.o keymgmt_meth.o
IPLIBOBJECTS += m_null.o m_sigver.o mac_lib.o mac_meth.o names.o
IPLIBOBJECTS += p5_crpt2.o p5_crpt.o
IPLIBOBJECTS += p_dec.o p_enc.o p_legacy.o p_lib.o p_open.o p_seal.o p_sign.o p_verify.o
IPLIBOBJECTS += pbe_scrypt.o pmeth_check.o pmeth_gn.o pmeth_lib.o signature.o
IPLIBOBJECTS += legacy_blake2.o legacy_md2.o legacy_md4.o legacy_md5.o
IPLIBOBJECTS += legacy_md5_sha1.o legacy_mdc2.o legacy_ripemd.o
IPLIBOBJECTS += legacy_sha.o legacy_wp.o

#crypto-ffc
IPLIBOBJECTS += ffc_backend.o ffc_dh.o ffc_key_generate.o ffc_key_validate.o
IPLIBOBJECTS += ffc_params_validate.o ffc_params.o ffc_params_generate.o

#hmac & http	& kdf		& 	lhash
IPLIBOBJECTS += hmac.o http_lib.o http_client.o http_err.o kdf_err.o lh_stats.o lhash.o

# md2
ifneq ($(IPCRYPTO_NO_MD2),yes)
IPLIBOBJECTS += md2_dgst.o  md2_one.o
endif

# md4
ifneq ($(IPCRYPTO_NO_MD4),yes)
IPLIBOBJECTS += md4_dgst.o md4_one.o
endif

# md5
ifneq ($(IPCRYPTO_NO_MD5),yes)
IPLIBOBJECTS += md5_dgst.o md5_one.o md5_sha1.o

ifeq ($(OPENSSL102_USE_ASM_ITL),yes)
ifndef _WRS_CONFIG_LP64
IPLIBOBJECTS +=mx86-elf.o
else
IPLIBOBJECTS +=md5-x86_64.o
endif
endif
endif

# modes
IPLIBOBJECTS += cbc128.o ccm128.o cfb128.o ctr128.o cts128.o gcm128.o ocb128.o ofb128.o
IPLIBOBJECTS += siv128.o wrap128.o xts128.o

# objects
IPLIBOBJECTS += o_names.o obj_dat.o obj_err.o obj_lib.o obj_xref.o

# ocsp
IPLIBOBJECTS += ocsp_asn.o ocsp_cl.o ocsp_err.o ocsp_ext.o ocsp_http.o
IPLIBOBJECTS += ocsp_lib.o ocsp_prn.o ocsp_srv.o ocsp_vfy.o v3_ocsp.o

# pem
IPLIBOBJECTS += pem_all.o pem_err.o pem_info.o pem_lib.o pem_oth.o pem_pk8.o
IPLIBOBJECTS += pem_pkey.o pem_sign.o pem_x509.o pem_xaux.o pvkfmt.o

#crypto-pkcs7
IPLIBOBJECTS += bio_pk7.o pk7_asn1.o pk7_attr.o pk7_doit.o pk7_lib.o pk7_mime.o
IPLIBOBJECTS += pk7_smime.o pkcs7err.o

#crypto-pkcs12
IPLIBOBJECTS += p12_add.o p12_asn.o p12_attr.o p12_crpt.o p12_crt.o p12_decr.o p12_init.o
IPLIBOBJECTS += p12_key.o p12_kiss.o p12_mutl.o p12_npas.o p12_p8d.o p12_p8e.o p12_sbag.o
IPLIBOBJECTS += p12_utl.o pk12err.o

#crypto-poly1305
IPLIBOBJECTS += poly1305.o
#IPLIBOBJECTS += poly1305_base2_44.o	???
#IPLIBOBJECTS += poly1305_ieee754.o	???
#IPLIBOBJECTS += poly1305_ppc.o	???


# crypto-property
IPLIBOBJECTS += defn_cache.o property.o property_err.o property_parse.o
IPLIBOBJECTS += property_query.o property_string.o

# rand
IPLIBOBJECTS += prov_seed.o rand_egd.o rand_err.o rand_lib.o rand_meth.o rand_pool.o
IPLIBOBJECTS += randfile.o rand_deprecated.o

# rc2
ifneq ($(IPCRYPTO_NO_RC2),yes)
IPLIBOBJECTS += rc2_cbc.o rc2_ecb.o rc2_skey.o rc2cfb64.o rc2ofb64.o
endif

# rc4
ifneq ($(IPCRYPTO_NO_RC4),yes)
IPLIBOBJECTS += rc4_enc.o rc4_skey.o
endif

# rc5
ifneq ($(IPCRYPTO_NO_RC5),yes)
#IPLIBOBJECTS += rc5_ecb.o rc5_enc.o rc5_skey.o rc5cfb64.o rc5ofb64.o
endif

# ripemd
ifneq ($(IPCRYPTO_NO_RIPEMD),yes)
IPLIBOBJECTS += rmd_dgst.o rmd_one.o
endif

#crypto-rsa
IPLIBOBJECTS += rsa_ameth.o rsa_asn1.o rsa_backend.o rsa_chk.o rsa_crpt.o rsa_depr.o rsa_err.o
IPLIBOBJECTS += rsa_gen.o rsa_lib.o rsa_meth.o rsa_mp.o rsa_mp_names.o  rsa_none.o
IPLIBOBJECTS += rsa_oaep.o rsa_ossl.o rsa_pk1.o rsa_pmeth.o rsa_prn.o rsa_pss.o
IPLIBOBJECTS += rsa_saos.o rsa_schemes.o rsa_sign.o rsa_x931.o rsa_x931g.o
IPLIBOBJECTS += rsa_sp800_56b_gen.o
IPLIBOBJECTS += rsa_sp800_56b_check.o

# seed
IPLIBOBJECTS += seed.o seed_cbc.o seed_cfb.o seed_ecb.o seed_ofb.o

# sha
IPLIBOBJECTS += keccak1600.o sha1_one.o sha1dgst.o sha3.o sha256.o sha512.o
IPLIBOBJECTS += sha_ppc.o

#crypto-siphash
IPLIBOBJECTS += siphash.o

#crypto-sm3
IPLIBOBJECTS += sm3.o legacy_sm3.o

#crypto-sm4
IPLIBOBJECTS += sm4.o

# srp
IPLIBOBJECTS += srp_lib.o srp_vfy.o

# stack
IPLIBOBJECTS += stack.o

# crypto-store
IPLIBOBJECTS += store_err.o store_init.o store_lib.o store_meth.o store_register.o store_result.o
IPLIBOBJECTS += store_strings.o

# ts
IPLIBOBJECTS += ts_asn1.o ts_conf.o ts_err.o ts_lib.o ts_req_print.o ts_rsp_utils.o
IPLIBOBJECTS += ts_rsp_print.o ts_rsp_sign.o ts_req_utils.o ts_rsp_verify.o ts_verify_ctx.o

# txt_db
IPLIBOBJECTS += txt_db.o

# ui
IPLIBOBJECTS += ui_err.o ui_lib.o ui_null.o ui_openssl.o ui_util.o

# whrlpool
IPLIBOBJECTS += wp_block.o wp_dgst.o

# x509
IPLIBOBJECTS += by_dir.o by_file.o by_store.o pcy_cache.o pcy_data.o pcy_lib.o
IPLIBOBJECTS += pcy_map.o pcy_node.o pcy_tree.o t_crl.o t_req.o t_x509.o
IPLIBOBJECTS += v3_addr.o v3_admis.o v3_akeya.o v3_akid.o v3_asid.o
IPLIBOBJECTS += v3_bcons.o v3_bitst.o v3_conf.o v3_cpols.o v3_crld.o
IPLIBOBJECTS += v3_enum.o v3_extku.o v3_genn.o v3_ia5.o
IPLIBOBJECTS += v3_info.o
IPLIBOBJECTS += v3_int.o
IPLIBOBJECTS += v3_ist.o
IPLIBOBJECTS += v3_lib.o
IPLIBOBJECTS += v3_ncons.o
IPLIBOBJECTS += v3_pci.o
IPLIBOBJECTS += v3_pcia.o
IPLIBOBJECTS += v3_pcons.o
IPLIBOBJECTS += v3_pku.o
IPLIBOBJECTS += v3_pmaps.o
IPLIBOBJECTS += v3_prn.o
IPLIBOBJECTS += v3_purp.o
IPLIBOBJECTS += v3_san.o
IPLIBOBJECTS += v3_skid.o
IPLIBOBJECTS += v3_sxnet.o
IPLIBOBJECTS += v3_tlsf.o
IPLIBOBJECTS += v3_utf8.o
IPLIBOBJECTS += v3_utl.o
IPLIBOBJECTS += v3err.o
IPLIBOBJECTS += x509_att.o
IPLIBOBJECTS += x509_cmp.o
IPLIBOBJECTS += x509_d2.o
IPLIBOBJECTS += x509_def.o
IPLIBOBJECTS += x509_err.o
IPLIBOBJECTS += x509_ext.o
IPLIBOBJECTS += x509_lu.o
IPLIBOBJECTS += x509_meth.o
IPLIBOBJECTS += x509_obj.o
IPLIBOBJECTS += x509_r2x.o
IPLIBOBJECTS += x509_req.o
IPLIBOBJECTS += x509_set.o
IPLIBOBJECTS += x509_trust.o
IPLIBOBJECTS += x509_txt.o
IPLIBOBJECTS += x509_v3.o
IPLIBOBJECTS += x509_vfy.o
IPLIBOBJECTS += x509_vpm.o
IPLIBOBJECTS += x509cset.o
IPLIBOBJECTS += x509name.o
IPLIBOBJECTS += x509rset.o
IPLIBOBJECTS += x509spki.o
IPLIBOBJECTS += x509type.o
IPLIBOBJECTS += x_all.o
IPLIBOBJECTS += x_attrib.o
IPLIBOBJECTS += x_crl.o
IPLIBOBJECTS += x_exten.o
IPLIBOBJECTS += x_name.o
IPLIBOBJECTS += x_pubkey.o
IPLIBOBJECTS += x_req.o
IPLIBOBJECTS += x_x509.o
IPLIBOBJECTS += x_x509a.o

#crypto/ec
IPLIBOBJECTS	+= 	curve25519.o ec2_oct.o ec2_smpl.o ec_ameth.o ec_check.o ec_curve.o ec_cvt.o ec_deprecated.o ec_mult.o ec_oct.o
IPLIBOBJECTS	+= 	ec_pmeth.o ec_print.o ecdh_kdf.o ecdh_ossl.o ecdsa_ossl.o ecdsa_sign.o ecdsa_vrf.o eck_prn.o ecp_mont.o
IPLIBOBJECTS	+= 	ecp_nist.o ecp_nistputil.o 
IPLIBOBJECTS	+= 	ecp_oct.o ecp_ppc.o ecp_s390x_nistp.o ecp_smpl.o ecx_backend.o ecx_s390x.o
IPLIBOBJECTS	+= 	ec_asn1.o ec_kmeth.o ec_err.o ec_key.o ec_backend.o ec_lib.o ecx_meth.o ecx_key.o ec_kmgmt.o  ecx_kmgmt.o
IPLIBOBJECTS	+= 	curve448.o curve448_tables.o eddsa.o scalar.o  f_impl32.o f_impl64.o f_generic.o
#IPLIBOBJECTS	+= 	 ecp_nistp224.o  ecp_nistp256.o ecp_nistp521.o  ecp_nistz256.o ecp_nistz256_table.o

#provider common der ec
IPLIBOBJECTS	+= 	der_ec_gen.o der_ec_key.o der_ec_sig.o der_ecx_gen.o der_ecx_key.o der_sm2_gen.o der_sm2_key.o der_sm2_sig.o

#evp cms ec
IPLIBOBJECTS	+= 	ec_ctrl.o cms_ec.o 

#crypto/sm2
IPLIBOBJECTS	+= 	sm2_crypt.o sm2_err.o sm2_key.o sm2_sign.o

#crypto-root
#IPLIBOBJECTS += armcap.o
IPLIBOBJECTS += asn1_dsa.o
IPLIBOBJECTS += bsearch.o
IPLIBOBJECTS += context.o
IPLIBOBJECTS += core_algorithm.o
IPLIBOBJECTS += core_fetch.o
IPLIBOBJECTS += core_namemap.o
IPLIBOBJECTS += cpt_err.o
IPLIBOBJECTS += cpuid.o
IPLIBOBJECTS += cryptlib.o
IPLIBOBJECTS += ctype.o
IPLIBOBJECTS += cversion.o
IPLIBOBJECTS += der_writer.o
IPLIBOBJECTS += dllmain.o
IPLIBOBJECTS += ebcdic.o
IPLIBOBJECTS += ex_data.o
IPLIBOBJECTS += ffc_params.o
IPLIBOBJECTS += getenv.o
IPLIBOBJECTS += info.o
IPLIBOBJECTS += init.o
IPLIBOBJECTS += initthread.o
#IPLIBOBJECTS += LPdir_unix.o			#??????????????????????
IPLIBOBJECTS += mem.o
IPLIBOBJECTS += mem_clr.o
IPLIBOBJECTS += mem_sec.o
IPLIBOBJECTS += o_dir.o
IPLIBOBJECTS += o_fopen.o
IPLIBOBJECTS += o_init.o
IPLIBOBJECTS += o_str.o
IPLIBOBJECTS += o_time.o
IPLIBOBJECTS += packet.o
IPLIBOBJECTS += param_build.o
IPLIBOBJECTS += param_build_set.o
IPLIBOBJECTS += params.o
IPLIBOBJECTS += params_dup.o
IPLIBOBJECTS += params_from_text.o
IPLIBOBJECTS += passphrase.o
#IPLIBOBJECTS += ppccap.o		#?????????????
IPLIBOBJECTS += provider.o
IPLIBOBJECTS += provider_child.o
IPLIBOBJECTS += provider_conf.o	
IPLIBOBJECTS += provider_core.o
IPLIBOBJECTS += provider_predefined.o
IPLIBOBJECTS += punycode.o
#IPLIBOBJECTS += s390xcap.o		#?????????????
IPLIBOBJECTS += self_test_core.o
#IPLIBOBJECTS += sparcv9cap.o		#?????????????
IPLIBOBJECTS += sparse_array.o
IPLIBOBJECTS += threads_lib.o
IPLIBOBJECTS += threads_none.o
IPLIBOBJECTS += trace.o
IPLIBOBJECTS += uid.o
IPLIBOBJECTS += ossl_core_bio.o
IPLIBOBJECTS += ec_support.o		
IPLIBOBJECTS += bn_rsa_fips186_4.o
IPLIBOBJECTS += rsa_mp_names.o
IPLIBOBJECTS += rsa_schemes.o
IPLIBOBJECTS += bf_prefix.o
IPLIBOBJECTS += passphrase.o
IPLIBOBJECTS += bio_sock2.o
IPLIBOBJECTS += bf_readbuff.o
IPLIBOBJECTS += property_query.o
IPLIBOBJECTS += ossl_core_bio.o
IPLIBOBJECTS += property.o

#provider root
IPLIBOBJECTS += baseprov.o defltprov.o legacyprov.o nullprov.o prov_running.o

#provider common
IPLIBOBJECTS += bio_prov.o capabilities.o digest_to_nid.o provider_ctx.o
IPLIBOBJECTS += provider_err.o provider_seeding.o provider_util.o securitycheck.o
IPLIBOBJECTS += securitycheck_default.o securitycheck_fips.o

#provider common der
IPLIBOBJECTS += der_digests_gen.o der_dsa_gen.o der_dsa_key.o der_dsa_sig.o
IPLIBOBJECTS += der_rsa_gen.o der_rsa_key.o der_rsa_sig.o der_sm2_gen.o
IPLIBOBJECTS += der_wrap_gen.o der_writer.o

#provider asymciphers
IPLIBOBJECTS += rsa_enc.o sm2_enc.o

#provider ciphers
IPLIBOBJECTS += cipher_aes.o cipher_aes_cbc_hmac_sha1_hw.o cipher_aes_cbc_hmac_sha256_hw.o
IPLIBOBJECTS += cipher_aes_cbc_hmac_sha.o cipher_aes_ccm.o cipher_aes_ccm_hw.o
IPLIBOBJECTS += cipher_aes_gcm.o cipher_aes_gcm_hw.o cipher_aes_hw.o
IPLIBOBJECTS += cipher_aes_ocb.o cipher_aes_ocb_hw.o cipher_aes_siv.o
IPLIBOBJECTS += cipher_aes_siv_hw.o cipher_aes_wrp.o cipher_aes_xts.o
IPLIBOBJECTS += cipher_aes_xts_fips.o cipher_aes_xts_hw.o cipher_aria.o
IPLIBOBJECTS += cipher_aria_ccm.o cipher_aria_ccm_hw.o cipher_aria_gcm.o
IPLIBOBJECTS += cipher_aria_gcm_hw.o cipher_aria_hw.o cipher_blowfish.o
IPLIBOBJECTS += cipher_blowfish_hw.o cipher_camellia.o cipher_camellia_hw.o
IPLIBOBJECTS += cipher_cast5.o cipher_cast5_hw.o cipher_chacha20.o cipher_chacha20_hw.o
IPLIBOBJECTS += cipher_chacha20_poly1305.o cipher_chacha20_poly1305_hw.o cipher_cts.o
IPLIBOBJECTS += cipher_des.o cipher_des_hw.o cipher_desx.o cipher_desx_hw.o
IPLIBOBJECTS += cipher_idea.o cipher_idea_hw.o cipher_null.o cipher_rc2.o cipher_rc2_hw.o cipher_rc4.o
IPLIBOBJECTS += cipher_rc4_hmac_md5.o cipher_rc4_hmac_md5_hw.o cipher_rc4_hw.o cipher_seed.o cipher_seed_hw.o
IPLIBOBJECTS += cipher_sm4.o cipher_sm4_hw.o cipher_tdes.o cipher_tdes_common.o
IPLIBOBJECTS += cipher_tdes_default.o cipher_tdes_default_hw.o cipher_tdes_hw.o
IPLIBOBJECTS += cipher_tdes_wrap.o cipher_tdes_wrap_hw.o ciphercommon.o
IPLIBOBJECTS += ciphercommon_block.o ciphercommon_ccm.o ciphercommon_ccm_hw.o
IPLIBOBJECTS += ciphercommon_gcm.o ciphercommon_gcm_hw.o ciphercommon_hw.o

#provider digests
IPLIBOBJECTS += blake2_prov.o blake2b_prov.o blake2s_prov.o digestcommon.o md2_prov.o
IPLIBOBJECTS += md4_prov.o md5_prov.o md5_sha1_prov.o mdc2_prov.o null_prov.o
IPLIBOBJECTS += ripemd_prov.o sha2_prov.o sha3_prov.o sm3_prov.o wp_prov.o

#provider encode_decode
IPLIBOBJECTS += decode_der2key.o decode_epki2pki.o decode_msblob2key.o decode_pem2der.o
IPLIBOBJECTS += decode_pvk2key.o decode_spki2typespki.o encode_key2any.o
IPLIBOBJECTS += encode_key2blob.o encode_key2ms.o encode_key2text.o endecoder_common.o

#provider exchange
IPLIBOBJECTS += dh_exch.o ecdh_exch.o ecx_exch.o kdf_exch.o

#provider kdfs
IPLIBOBJECTS += hkdf.o kbkdf.o krb5kdf.o pbkdf1.o pbkdf2.o pbkdf2_fips.o pkcs12kdf.o scrypt.o
IPLIBOBJECTS += sshkdf.o sskdf.o tls1_prf.o x942kdf.o

#provider kem
IPLIBOBJECTS += rsa_kem.o

#provider keymgmt
IPLIBOBJECTS += dh_kmgmt.o dsa_kmgmt.o kdf_legacy_kmgmt.o mac_legacy_kmgmt.o
IPLIBOBJECTS += rsa_kmgmt.o

#provider macs
IPLIBOBJECTS += blake2_mac_impl.o blake2b_mac.o blake2s_mac.o cmac_prov.o gmac_prov.o
IPLIBOBJECTS += hmac_prov.o kmac_prov.o poly1305_prov.o siphash_prov.o

#provider rands
IPLIBOBJECTS += crngt.o drbg.o drbg_ctr.o drbg_hash.o drbg_hmac.o seed_src.o test_rng.o

#provider rands seeding
IPLIBOBJECTS += rand_vxworks.o

#provider signature
IPLIBOBJECTS += dsa_sig.o ecdsa_sig.o eddsa_sig.o mac_legacy_sig.o rsa_sig.o sm2_sig.o

#provider storemgmt
IPLIBOBJECTS += file_store.o file_store_any2obj.o

ifneq ($(IPCRYPTO_NO_EC),yes)
# ec
IPLIBOBJECTS += ec2_mult.o
IPLIBOBJECTS += ec2_oct.o
IPLIBOBJECTS += ec2_smpl.o
IPLIBOBJECTS += ec_ameth.o
IPLIBOBJECTS += ec_asn1.o
IPLIBOBJECTS += ec_check.o
IPLIBOBJECTS += ec_curve.o
IPLIBOBJECTS += ec_cvt.o
IPLIBOBJECTS += ec_err.o
IPLIBOBJECTS += ec_key.o
IPLIBOBJECTS += ec_lib.o
IPLIBOBJECTS += ec_mult.o
IPLIBOBJECTS += ec_oct.o
IPLIBOBJECTS += ec_pmeth.o
IPLIBOBJECTS += ec_print.o
IPLIBOBJECTS += eck_prn.o
IPLIBOBJECTS += ecp_mont.o
IPLIBOBJECTS += ecp_nist.o
IPLIBOBJECTS += ecp_nistp224.o
IPLIBOBJECTS += ecp_nistp256.o
IPLIBOBJECTS += ecp_nistp521.o
IPLIBOBJECTS += ecp_nistputil.o
IPLIBOBJECTS += ecp_nistz256.o
IPLIBOBJECTS += ecp_oct.o
IPLIBOBJECTS += ecp_smpl.o

# ecdh
IPLIBOBJECTS += ech_err.o
IPLIBOBJECTS += ech_kdf.o
IPLIBOBJECTS += ech_key.o
IPLIBOBJECTS += ech_lib.o
IPLIBOBJECTS += ech_ossl.o

# ecdsa
IPLIBOBJECTS +=  ecs_asn1.o
IPLIBOBJECTS +=  ecs_err.o
IPLIBOBJECTS +=  ecs_lib.o
IPLIBOBJECTS +=  ecs_ossl.o
IPLIBOBJECTS +=  ecs_sign.o
IPLIBOBJECTS +=  ecs_vrf.o
endif
#############################################################################
# SOURCE
###########################################################################
#add extra dir from 3
IPSRCDIRS 	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto
IPSRCDIRS 	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/async
IPSRCDIRS 	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/async/arch
IPSRCDIRS 	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/cmp
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/conf
IPSRCDIRS 	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/crmf
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md2
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md4
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md5
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/sha
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/mdc2
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/hmac
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ripemd
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/des
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rc2
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rc4
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/bf
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/cast
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/bn
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ec
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ec/curve448
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ec/curve448\arch_32
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ec/curve448\arch_64

IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ecdh
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ecdsa
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rsa
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/dsa
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/dh
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/dso
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/engine
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/aes
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/buffer
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/bio
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/stack
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/lhash
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rand
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/err
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ess
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/objects
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/evp
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/asn1
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/pem
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/x509
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/x509v3
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/txt_db
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/pkcs7
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/pkcs12
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/comp
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ocsp
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ui
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/krb5
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/pqueue
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/sm2
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ts
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/cmac
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/cms
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/modes
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/seed
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/srp
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/whrlpool
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/camellia
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/idea
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/jpake
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/pool
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rc5
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/store
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/encode_decode
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ffc
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/http
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/property
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ct
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/sm3
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/poly1305
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/siphash
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/aria
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/chacha
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/sm4
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/kdf

IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/common
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/common/der

IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/asymciphers
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/ciphers
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/digests
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/encode_decode
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/exchange
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/kdfs
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/kem
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/keymgmt
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/macs
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/rands
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/rands/seeding
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/signature
IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/providers/implementations/storemgmt

IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/aes
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/bf
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/bn
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/cast
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/des
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md5
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/md4
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/rc4
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/ripemd
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/sha
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/modes
IPASDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/crypto/whrlpool
#IPSRCDIRS	+= $(IPCRYPTO_OPENSSL_ROOT)/engines
#############################################################################
# END OF IPCRYPTO_OBJS.MK
#############################################################################

