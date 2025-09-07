#if 0
#include <assert.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include <openssl/e_os2.h>
#ifdef OPENSSL_NO_STDIO
#define APPS_WIN16
#endif

/* With IPv6, it looks like Digital has mixed up the proper order of
   recursive header file inclusion, resulting in the compiler complaining
   that u_int isn't defined, but only if _POSIX_C_SOURCE is defined, which
   is needed to have fileno() declared correctly...  So let's define u_int */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__U_INT)
#define __U_INT
typedef unsigned int u_int;
#endif

#define USE_SOCKETS
#include "apps.h"

#include <openssl/x509.h>


#include <openssl/ssl.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_SRP
#include <openssl/srp.h>
#endif
#include "s_apps.h"
#include "timeouts.h"

#define SOCKET_PROTOCOL IPPROTO_TCP

enum { 
	s_client_exec, 
	s_server_exec,
	s_test_client,
	s_test_server,
	s_ciphers,
	s_genrsa,
	s_dsaparam,
	s_dhparam
}ex_num;


int ssl_run_cmd(char *cmd_str);
int parse_argstr(char *arg_str, int *argc, char ***argv);

extern int genrsa_main(int argc, char *argv[]);
extern int dsaparam_main(int argc, char *argv[]);
extern int dhparam_main(int argc, char *argv[]);
extern int speed_main(int argc, char *argv[]);

#if 0
extern int ssltest_main(int argc, char *argv[]);
#endif

extern int s_client_main(int argc, char **argv);
extern int s_server_main(int argc, char *argv[]);
extern int rsa_main(int argc, char *argv[]);
extern int gendsa_main(int argc, char **argv);
extern void cryptotest(void);

int ssl_test_server(void);



int crypto_init(void)
{
    static int init = 0;
    char uninitialized_buf[32];

    /*if(init == 0)*/
    {
        init = 1;

#if 1
	CRYPTO_set_locking_callback(NULL);
        ENGINE_load_builtin_engines();
#endif

        /* Dummy seed to make RAND functions operational */
        RAND_seed((char *) uninitialized_buf, sizeof(uninitialized_buf));
    ssl_load_ciphers();
	SSL_library_init();
    }
    return 0;
}


#define STRING_SSLTEST_SSLV2  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl2"

#define STRING_SSLTEST_SSLV3  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3"
#define STRING_SSLTEST_SSLV3SA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -server_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_SSLV3CA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -client_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_SSLV3CSA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -server_auth -client_auth -CAfile ca-cert.pem"

#define STRING_SSLTEST_TLS  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1"
#define STRING_SSLTEST_TLSSA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1 -server_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_TLSCA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1 -client_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_TLSCSA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -tls1 -server_auth -client_auth -CAfile ca-cert.pem"

#define STRING_SSLTEST_AUTONEG  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem"
#define STRING_SSLTEST_AUTONEGSA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -server_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_AUTONEGCA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -client_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_AUTONEGCSA  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -server_auth -client_auth -CAfile ca-cert.pem"

#define STRING_SSLTEST_SSLV3BIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3 -bio_pair"
#define STRING_SSLTEST_SSLV3SABIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3  -bio_pair -server_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_SSLV3CABIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3  -bio_pair -client_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_SSLV3CSABIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem -ssl3  -bio_pair -server_auth -client_auth -CAfile ca-cert.pem"

#define STRING_SSLTEST_AUTONEGBIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair"
#define STRING_SSLTEST_AUTONEGSABIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -server_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_AUTONEGCABIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -client_auth -CAfile ca-cert.pem"
#define STRING_SSLTEST_AUTONEGCSABIO  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -server_auth -client_auth -CAfile ca-cert.pem"

#define STRING_SSLTEST_SSLBIONODHE  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -no_dhe"
#define STRING_SSLTEST_SSLBIODHE  "ssltest -key server-key.pem -cert server-cert.pem -c_key client-key.pem -c_cert client-cert.pem  -bio_pair -dhe1024dsa"



int ssltest_run_cmd(char *cmd_str)
{
    if (NULL == cmd_str)
	return 1;

    if(0==strcmp(cmd_str, "sslv2"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV2, 1, 2,3,4,5,6,7,8,9);
    }
    else if(0==strcmp(cmd_str, "sslv3"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3, 1, 2,3,4,5,6,7,8,9);
    }		
    else if(0==strcmp(cmd_str, "sslv3sa"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3SA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "sslv3ca"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3CA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "sslv3csa"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3CSA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "tls"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_TLS, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "tlssa"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_TLSSA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "tlsca"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_TLSCA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "tlscsa"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_TLSCSA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "autoneg"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEG, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "autonegsa"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEGSA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "autonegca"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEGCA, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "autonegcsa"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEGCSA, 1, 2,3,4,5,6,7,8,9);
    }
    else if(0==strcmp(cmd_str, "sslv3bio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3BIO, 1, 2,3,4,5,6,7,8,9);
    }		
    else if(0==strcmp(cmd_str, "sslv3sabio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3SABIO, 1, 2,3,4,5,6,7,8,9);    
    }		
    else if(0==strcmp(cmd_str, "sslv3cabio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3CABIO, 1, 2,3,4,5,6,7,8,9);    
    }		
    else if(0==strcmp(cmd_str, "sslv3csabio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLV3CSABIO, 1, 2,3,4,5,6,7,8,9);    
    }		
    else if(0==strcmp(cmd_str, "autonegbio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEGBIO, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "autonegsabio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEGSABIO, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "autonegcabio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEGCABIO, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "autonegcsabio"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_AUTONEGCSABIO, 1, 2,3,4,5,6,7,8,9);    
    }
    else if(0==strcmp(cmd_str, "sslbionodhe"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLBIONODHE, 1, 2,3,4,5,6,7,8,9);    
    }		
    else if(0==strcmp(cmd_str, "sslbiodhe"))
    {
	taskSpawn("ssltest",
		  100,
		  0,
		  1024 * 1024, /* big stack */
		  ssl_run_cmd,
		  STRING_SSLTEST_SSLBIODHE, 1, 2,3,4,5,6,7,8,9);    
    }
    else
    {
    	printf("%s not support.\r\n ", cmd_str);
    }

    return 0;
}


int ssl_run_cmd(char *cmd_str)
{
    int i;
    int argc;
    char** argv = NULL;
    int rc = 0;

    if (NULL == cmd_str)
	return 1;

    switch (parse_argstr(cmd_str, &argc, &argv))
    {
	    case 0:
	        break;
	    default:
	        goto out;
    }

   if( (argc == 0) || (argv==NULL) )
   	return 1;
#if 0
    printf("\r\ncmd details(%d options): \r\n", argc-1);
    for(i=0; i<argc; i++)
    {
    	printf("%s ", argv[i]);
    }
    printf("\r\n");
#endif

#if 0	
	crypto_init();

	if(0==strcmp(argv[0], "asn1parse"))
	{
		asn1parse_main(argc, argv);
	}
	
	else if(0==strcmp(argv[0], "ssltest"))
	{
		ssltest_main(argc, argv);
	}
#endif

	if(0==strcmp(argv[0], "ciphers"))
	{
		ciphers_main(argc, argv);
	}	
	else if(0==strcmp(argv[0], "genrsa"))
	{
#ifndef OPENSSL_NO_RSA
		genrsa_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif
	}
	else if(0==strcmp(argv[0], "rsa"))
	{
#ifndef OPENSSL_NO_RSA
		rsa_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif
	}
	else if(0==strcmp(argv[0], "dsaparam"))
	{
#ifndef OPENSSL_NO_DSA
		dsaparam_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif
	}
	else if(0==strcmp(argv[0], "gendsa"))
	{
#ifndef OPENSSL_NO_DSA
		gendsa_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif
	}
	else if(0==strcmp(argv[0], "dsa"))
	{
#ifndef OPENSSL_NO_DSA
		dsa_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif
	}
	else if(0==strcmp(argv[0], "dhparam"))
	{
#ifndef OPENSSL_NO_DH
		dhparam_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif	
	}
	else if(0==strcmp(argv[0], "gendh"))
	{
#if 0	
#ifndef OPENSSL_NO_DH
		gendh_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif	
#endif
    		printf("%s not support.\r\n", argv[0]);
	}
	else if(0==strcmp(argv[0], "dh"))
	{
#ifndef OPENSSL_NO_DH
		dhparam_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif	
	}
	else if(0==strcmp(argv[0], "speed"))
	{
#if 1	
#ifndef OPENSSL_NO_SPEED
        int taskId;
        taskId = taskSpawn("speed", 100, 0, 100*1024, speed_main, argc, (int) argv,0,0,0,0,0,0,0,0);
return 0;
#endif

#else
    	printf("%s not support.\r\n", argv[0]);
#endif
	}
	else if(0==strcmp(argv[0], "cryptotest"))
	{
		taskSpawn("OpenSSL-Test",
				  100,
				  0,
				  1024 * 1024, /* big stack */
				  cryptotest,
				  0,1,2,3,4,5,6,7,8,9);
	}
	
	else if(0==strcmp(argv[0], "s_client"))
	{
#if !defined(OPENSSL_NO_SOCK)
		s_client_main(argc, argv);
#else
    		printf("%s not support.\r\n", argv[0]);
#endif
	}
	else if(0==strcmp(argv[0], "s_server"))
	{
#if 0	
#if !defined(OPENSSL_NO_SOCK)
		int taskId;
		taskId = taskSpawn ("s_server", 100, 0, 100*1024, (FUNCPTR)s_server_main, argc, (int) argv,0,0,0,0,0,0,0,0);
		return 0;
#else
    		printf("%s not support.\r\n", argv[0]);
#endif
#endif
	}

    if (argv)
        free(argv);
out:
    return rc;
}

#if 0
int ssl_test_client(void)		
{
    	int s,i;
	struct sockaddr_in them;
	unsigned long addr;
	char* teststring = "0123456789";

	memset((char *)&them,0,sizeof(them));
	them.sin_family=AF_INET;
	them.sin_port=htons((unsigned short)4433);
	addr=(unsigned long)0x7f000001;
	them.sin_addr.s_addr=htonl(addr);

	s=socket(AF_INET,SOCK_STREAM,SOCKET_PROTOCOL);
	if (s == INVALID_SOCKET) 
		{ printf("socket.\r\n"); return(0); }
	
	if (connect(s,(struct sockaddr *)&them,sizeof(them)) == -1)
		{ closesocket(s); printf("connect fail"); return(0); }		/*con fail*/
/*	*sock=s;*/
		printf("con ok.\r\n");
	writesocket(s,teststring,10);

}



int ssl_test_server(void)
{
	int ret=0;
	struct sockaddr_in server;
	int s= -1;

	memset((char *)&server,0,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons((unsigned short)4433);
	server.sin_addr.s_addr=0x7F000001;
	/*memcpy(&server.sin_addr,"7F000001",4);*/
	
	s=socket(AF_INET,SOCK_STREAM,SOCKET_PROTOCOL);

	if (s == INVALID_SOCKET) 
		goto err;
	
#if defined SOL_SOCKET && defined SO_REUSEADDR
	{
		int j = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			   (void *) &j, sizeof j);
	}
#endif
	if (bind(s,(struct sockaddr *)&server,sizeof(server)) == -1)
	{
		perror("bind");
		goto err;
	}
	/* Make it 128 for linux */
	if (listen(s,128) == -1) goto err;
/*	*sock=s;*/
	ret=1;
	return(ret);
err:
	if ((ret == 0) && (s != -1))
	{
		SHUTDOWN(s);
	}
	perror("fail");
	return(ret);
}
#endif


int parse_argstr(char *arg_str, int *argc, char ***argv)
{
    char **tmp_argv;
    unsigned long argv_size = 32;
    int pos = 0, arg_str_len;
    int err_code;
    char endmark;
    enum { skipping_space, searching_end_of_arg } state;

    state = skipping_space;
    *argc = 0;
    arg_str_len = strlen(arg_str);
    endmark = ' ';

    tmp_argv = malloc(sizeof(char *) * argv_size);
    if(tmp_argv == NULL)
    {
        err_code = 1;
        goto err;
    }
    memset(tmp_argv, 0, sizeof(char *) * argv_size);

    while(pos < arg_str_len)
    {
        switch(state)
        {
        case skipping_space:
            if(arg_str[pos] == ' ' || arg_str[pos] == '\t')
                break;
            if(arg_str[pos] == '\'')
            {
                endmark = '\'';
                pos++;
            }
            else if(arg_str[pos] == '"')
            {
                endmark = '"';
                pos++;
            }
            else
                endmark = ' ';

            tmp_argv[*argc] = &(arg_str[pos]);
            (*argc)++;
            if(*argc == (int)argv_size)
            {
                tmp_argv = realloc(tmp_argv, sizeof(char*)*argv_size*2);
                if( !tmp_argv )
                {
                    err_code = 1;
                    goto err;
                }
                argv_size *=2;
            }
            state = searching_end_of_arg;
            break;

        case searching_end_of_arg:
            if(arg_str[pos] == endmark)
            {
                state = skipping_space;
                arg_str[pos] = 0;
            }
            break;

        default:
            printf("critical error!!!");
            break;
        }
        pos++;
    }

    if(state == searching_end_of_arg && (endmark == '\'' || endmark == '"'))
    {
        err_code = 1;
        goto err;
    }
    tmp_argv[*argc] = NULL;

    *argv = tmp_argv;
    return 0;

 err:
    if(tmp_argv != NULL)
    {
        free(tmp_argv);
    }
    *argc = 0;
    *argv = NULL;
    return err_code;
}


