/* testDriver.c - OpenSSL Test Driver  */
/*
 * Copyright (c) Wind River Systems, Inc.
 */
#include <sys/types.h> 
#include <ipcom_type.h>
#include <ipcrypto_iptype_map.h>
#include <ipcrypto_config.h>
#include <ipcom_file.h>
#include <ipcom_time.h>
#include <ipcom_clib.h>
#include <sys/stat.h>
#include <openssl/opensslconf.h>  /* OPENSSL_NO_xxx macros */
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int test_cast(void);
int test_des(void);
int test_dh(void);

 int test_bf();
int test_ige();
int test_internal_bn(int i);
int test_exp(void);
int test_srp(void);
int test_dsa(void);



 int asn1test();
 int bntest(int argc, char *argv[]);
 int casttest();
 int destest();
 int dhtest();
 int dsatest();
 int ecdhtest();
 int ecdsatest();
 int ectest();
 int evp_test(int argc, char *argv[]);
 int exptest();
 int hmactest();
 int ideatest();
 #ifndef OPENSSL_NO_JPAKE
int jpaketest();
 #endif
 int lh_test();
 int md2test();
 int md4test();
 int md5test();
 int pq_test();
 int randtest();
 int rc2test();
 int rc4test();
 int rc5test();
 int rmdtest();
 int rsa_test();
 int sha256test();
 int sha512test();
 int shatest();
 int sha1test();
 int speed(int argc, char *argv[]);
 int srptest();

 #if 0
 int ssltest_main(int argc, char *argv[]);
#endif

 int v3nametest();
 int wptest();
#ifdef OPENSSL_FIPS
 int fips_test_suite_main(int argc, char *argv[]);
#endif
 void crypto_test();
 void ssl_test();
int ssltest(char * argString);
 
 void ENGINE_load_builtin_engines();
 void app_init();


char * testResultBuffer = NULL;
char * testResultTail = NULL;
#define TEST_PRINTF(...) 							\
	fprintf (stderr, __VA_ARGS__);					\
	testResultTail += sprintf(testResultTail, __VA_ARGS__);
/*
 * Define a helper macro to exit when a failure occurs
 */
#if 0 
#define VERIFY_TEST(x)                              \
	returnValue = x;                                \
	if (returnValue == 1)                           \
	{                                               \
		TEST_PRINTF("%s passed\n", #x);                  \
	}                                               \
	else                                            \
	{                                               \
		TEST_PRINTF("Failure in test %s!!\n", #x);       \
		return;                                     \
	} /* if */
#else
#define VERIFY_TEST(x)                              \
	returnValue = x;
#endif

/* This is the filename of the EVP test vector file.  It must be
in a location accessible to the test */
#define EVP_FILENAME "evptests.txt"


int fexist (char * filename)
{
  struct stat fstat;   
  return (stat (filename, &fstat) == 0) ? 1 : 0;
}

void cryptotest(void)
{
	int returnValue = 0;
	int argc = 0;
	char *argv[4];
	
	/* Large buffer to store test results */
	if ((testResultTail = testResultBuffer = (char *)calloc(1024, 1024)) == NULL)
	{
		printf("Error allocating test result buffer.  Terminating.\n");
		return;
	}
	
	for (argc=0; argc < 4; argc++)
		argv[argc] = (char *)calloc(1,256);
	
	TEST_PRINTF("\n\n *** Starting the %s Crypto Test ***\n",
                      OPENSSL_VERSION_TEXT);
	
	VERIFY_TEST(test_stack());		
	VERIFY_TEST(test_upcalls());		
	VERIFY_TEST(test_pkey_meth());	
	
	VERIFY_TEST(test_errstr());		
	
	VERIFY_TEST(test_internal_ctype());		
	VERIFY_TEST(test_internal_asn1_dsa());		
	VERIFY_TEST(test_internal_exts());		
	VERIFY_TEST(test_internal_chacha());	
	VERIFY_TEST(test_internal_sm3());		
	VERIFY_TEST(test_internal_sm4());		
	VERIFY_TEST(test_internal_ssl_cert_table());		
	
	VERIFY_TEST(test_lhash());		
	VERIFY_TEST(test_sparse_array());		
	VERIFY_TEST(test_test());
	
	VERIFY_TEST(test_asn1_string_table());		
	VERIFY_TEST(test_cmp_asn());		
	
	VERIFY_TEST(test_cmp_status());		
	VERIFY_TEST(test_bio_memleak());		
	VERIFY_TEST(test_constant_time());		
	VERIFY_TEST(test_pbelu());		

	/* 	AES Tests (igetest) */
	VERIFY_TEST(test_ige());							/*1/10 fail*/

	VERIFY_TEST(test_v3name());		
	VERIFY_TEST(test_asn1_time());		
#ifndef OPENSSL_NO_BF	
	/* Blowfish Tests (bftest) */
	VERIFY_TEST(test_bf());								/* 1/6 fail*/
#else
	TEST_PRINTF("BF test skipped due to OPENSSL_NO_BF\n");
#endif	
	
#ifndef OPENSSL_NO_CAST
	/* CAST Tests */
	VERIFY_TEST(test_cast());										/* 1/2 fail*/
#else
	TEST_PRINTF("CAST test skipped due to OPENSSL_NO_CAST\n");
#endif	

#ifndef OPENSSL_NO_DES
	/* DES Tests */
	VERIFY_TEST(test_des());										/* 4/24 fail*/
#else
	TEST_PRINTF("DES test skipped due to OPENSSL_NO_DES\n");
#endif	


	VERIFY_TEST(test_dh());										/* 9/9 fail*/
	
	
	VERIFY_TEST(test_dsa());										/* 5/5 fail*/
	
#ifndef OPENSSL_NO_EC
	VERIFY_TEST(test_ecstress());							/*ec not support*/
#else
	TEST_PRINTF("EC test skipped due to unclear patent situation\n");
#endif		

	VERIFY_TEST(test_evp());									/* 1/1 fail*/		/*exception*/			

	/* 	HMAC Tests (test_hmac) */
	VERIFY_TEST(test_hmac());							/* 5/6 fail*/

#ifndef OPENSSL_NO_IDEA
	/*	IDEA Test (ideatest) */
	VERIFY_TEST(test_idea());
#else
	TEST_PRINTF("IDEA test skipped due to OPENSSL_NO_IDEA\n");
#endif

#ifdef OPENSSL_NO_JPAKE_TEST
	TEST_PRINTF("skipped: JPAKE test is not supported by this OpenSSL build.\n");
#endif

	/*MD2, MD4, MD5 Tests*/
#ifdef OPENSSL_NO_MD2_TEST	
	TEST_PRINTF("skipped: MD2 test is not supported by this OpenSSL build.\n");
#endif

#ifdef OPENSSL_NO_MD4_TEST
	TEST_PRINTF("skipped: MD4 test is not supported by this OpenSSL build.\n");
#endif

#ifdef OPENSSL_NO_MD5_TEST
	TEST_PRINTF("skipped: MD5 test is not supported by this OpenSSL build.\n");
#endif

#if !defined(OPENSSL_NO_DES) && !defined(OPENSSL_NO_MDC2)
	VERIFY_TEST(test_internal_mdc2());				/*ec not support*/
#else
	TEST_PRINTF("MDC2 test skipped due to OPENSSL_NO_MDC2\n");	
#endif

	/* RAND Tests (test_rand) */
	VERIFY_TEST(test_rand());									/* 1/1 fail*/

	/* Whirlpool Hashing Tests (test_wpacket), */
	VERIFY_TEST(test_wpacket());
	

	/* RC2, RC4, RC5 Tests (rc2test, rc4test, rc5test)  */
#ifndef OPENSSL_NO_RC2
	VERIFY_TEST(test_rc2());									/* 1/1 fail*/
#else
	TEST_PRINTF("RC2 test skipped due to OPENSSL_NO_RC2\n");
#endif	
#ifndef OPENSSL_NO_RC4
	VERIFY_TEST(test_rc4());									/* 1/4 fail*/
#else
	TEST_PRINTF("RC4 test skipped due to OPENSSL_NO_RC4\n");
#endif	
#ifndef OPENSSL_NO_RC5
	VERIFY_TEST(test_rc5());		/*skipped: rc5 is not supported by this OpenSSL build*/
#else
	/*skipped: rc5 is not supported by this OpenSSL build*/
	TEST_PRINTF("skipped: rc5 is not supported by this OpenSSL build.\n");
#endif	

	VERIFY_TEST(test_rsa());									/* 4/4 fail*/			/*exception*/	

	/*include 256,512, etc*/
	VERIFY_TEST(test_sha());										/* 5/5 fail*/															


	TEST_PRINTF("OpenSSL test driver exiting...\n");
	printf("\n\nTest Summary:\n");
	
	puts(testResultBuffer);
}

void ssl_test()
{
	int returnValue = 0;
	int argc = 0;
	char *argv[4];
	struct Ip_timeval tv;

	/* Large buffer to store test results */
	if ((testResultTail = testResultBuffer = (char *)calloc(1024, 1024)) == NULL)
	{
		printf("Error allocating test result buffer.  Terminating.\n");
		return;
	}

	for (argc=0; argc < 4; argc++)
		argv[argc] = (char *)calloc(1,256);

	/* Set the clock to a time when the demo certs are active, as many vxWorks
	systems don't have a RTC */
	tv.tv_sec = 1483228800; /* Jan 1, 2017 */
	tv.tv_usec = 0;
	ipcom_settimeofday(&tv, NULL);

	TEST_PRINTF("\n\n *** Starting the %s SSL Test ***\n",
                      OPENSSL_VERSION_TEXT);

	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl2"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -server_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -server_auth -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1 -server_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1 -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1 -server_auth -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem "));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -server_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -server_auth -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -bio_pair "));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3  -bio_pair -server_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3  -bio_pair -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3  -bio_pair -server_auth -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair "));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -server_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -server_auth -client_auth -CAfile ca-cert.pem"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -no_dhe"));
	VERIFY_TEST(ssltest("-key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -dhe1024dsa"));

	TEST_PRINTF("OpenSSL test driver exiting...\n");
	printf("\n\nTest Summary:\n");

	puts(testResultBuffer);
}

typedef void (*ARGV_VOIDFUNCPTR)(int argc, char * argv[]);

void arg_call(ARGV_VOIDFUNCPTR pFunc, char *arg1, char * arg2, char * arg3, char *arg4, char * arg5, char * arg6)
{
	char * argv[7];
	int argc = 1;
	argv[0] = "dummy";
	argv[1] = arg1; if (arg1 != NULL) argc++;
	argv[2] = arg2; if (arg2 != NULL) argc++;
	argv[3] = arg3; if (arg3 != NULL) argc++;
	argv[4] = arg4; if (arg4 != NULL) argc++;
	argv[5] = arg5; if (arg5 != NULL) argc++;
	argv[6] = arg6; if (arg6 != NULL) argc++;

	(*pFunc)(argc, argv);

}

/* Parses the args into the argv array provided.  We assume that argv[0] is already filled in.
 * Note that to deal with C string literals, a new string is allocated.  Thus, if argc > 1,
 * argv[1] must be freed when done */
int parse_args(char * args_in, char * argv[])
{
	int argc = 1;
	char * ppLast = NULL;
	char * args; /* mutable copy of string */

    if (args_in == NULL)
		return 1;

	args = calloc(4096,1);
	strncpy(args, args_in, 4096);
	args[4095] = 0;

	if ((argv[argc++] = strtok_r(args, " ", &ppLast)) == NULL)
		return 1; /* no args */

	while ((argv[argc] = strtok_r(NULL, " ", &ppLast)) != NULL)
		argc ++;

	return argc;
}

/* Wrapper to parse args of ssltest */
int ssltest(char * args)
	{
	char * argv[128];
	int argc;

	argv[0] = "ssltest";
	argc = parse_args(args, argv);

#if 0	
	ssltest_main(argc, argv);
#endif

	if (argc > 1)
		free(argv[1]);
	return 0;
	}


#ifdef OPENSSL_FIPS
unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len);
/* This function checks the incore signature, and prints it out */
void FIPS_signature_get()
{
	unsigned char sig[EVP_MAX_MD_SIZE];
	unsigned int len, i;
	bfill((char *) sig, EVP_MAX_MD_SIZE, 0xee);
	len=FIPS_incore_fingerprint(sig,sizeof(sig));
	if (len == 0)
	{
		printf("Error getting FIPS signature\n");
	}
	printf("Signature = {");
	for (i=0; i<len; i++)
	{
		printf("0x%02x%s", sig[i], i==(len-1)?"}\n":", ");
	}
}

void fips_test_suite(char * args)
	{
	char * argv[128];
	int argc;

	bzero((char *)argv, 128*sizeof(char *));

	argv[0] = "fips_test_suite_main";
	argc = parse_args(args, argv);
	fips_test_suite_main(argc, argv);

	if (argc > 1)
		free(argv[1]);
	}
int  FIPS_selftest(void);
int fipsSelfTests(int unused)
{
    if (FIPS_selftest() == 1)
        return 0;
    else
        return 1;

}	
#endif
/* A simple test program to demonstrate that threadids are working.  
This simply prints the current threadid - calling it twice from 
different tasks will be needed */
void print_openssl_thread_id()
{
	CRYPTO_THREADID tid;
	CRYPTO_THREADID_current(&tid);
	printf("ThreadID = %x\n", CRYPTO_THREADID_hash(&tid));
	taskDelay(sysClkRateGet() * 20);
}
