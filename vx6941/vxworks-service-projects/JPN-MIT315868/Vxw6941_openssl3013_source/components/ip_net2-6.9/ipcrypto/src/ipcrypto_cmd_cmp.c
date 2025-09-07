/*
 ******************************************************************************
 *                     SOURCE FILE
 *
 *     Document no: @(#) $Name: VXWORKS_ITER29_2014062011 $ $RCSfile: ipcrypto_cmd_cmp.c,v $ $Revision: 1.6 $
 *     $Source: /home/interpeak/CVSRoot/ipcrypto/src/ipcrypto_cmd_cmp.c,v $
 *     $Author: rboden $ $Date: 2009-04-22 08:25:43 $
 *     $State: Exp $ $Locker:  $
 *
 *     Copyright Interpeak AB 2000-2002 <www.interpeak.se>. All rights reserved.
 *            Ported to IPCOM by Lennart Bang <lob@interpeak.se>
 ******************************************************************************
 */

/*
 ****************************************************************************
 * 1                    COPYRIGHTS
 ****************************************************************************
 * Copyright (c) 1987, 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


/*
 ****************************************************************************
 * 3                    INCLUDE FILES
 ****************************************************************************
 */

#define IPCOM_USE_CLIB_PROTO
#include <ipcom_getopt.h>
#include <ipcom_file.h>
#include <ipcom_clib.h>
#include <ipcom_clib2.h>


/*
 ****************************************************************************
 * 5                    DEFINES
 ****************************************************************************
 */
#define   SIZE_T_MAX      UINT_MAX        /* max value for a size_t */

#define OK_EXIT		0
#define DIFF_EXIT	10
#define ERR_EXIT	20	/* error exit code */

#define MIN(a,b) (((a) < (b)) ? (a) : (b))


/*
 ****************************************************************************
 * 6                    TYPES
 ****************************************************************************
 */


/*
 ****************************************************************************
 * 7                    LOCAL PROTOTYPES
 ****************************************************************************
 */
static void usage(void);
static void c_special(int fd1, char *file1, Ip_off_t skip1, int fd2, char *file2, Ip_off_t skip2);
static void eofmsg(char *file);
static void diffmsg(char *file1, char *file2, Ip_off_t byte, Ip_off_t line);

int ipcrypto_cmd_cmp(int argc, char **argv);

/*
 ****************************************************************************
 * 8                    DATA
 ****************************************************************************
 */
static int lflag, sflag;

static const char __progname[] = "cmp";


/*
 ****************************************************************************
 * 9                    FUNCTIONS
 ****************************************************************************
 */

/*
 *===========================================================================
 *                         errx
 *===========================================================================
 */
static void
errx(int eval, const char *fmt, ...)
{
    va_list ap;

    ipcom_fprintf(ip_stderr, "%s", __progname);
    if(fmt != IP_NULL)
        ipcom_fprintf(ip_stderr, ": ");
    if (fmt != IP_NULL)
    {
        va_start(ap, fmt);
        ipcom_vfprintf(ip_stderr, fmt, ap);
        va_end(ap);
    }
    ipcom_fprintf(ip_stderr, IP_LF);

    ipcom_exit(eval);
}


/*
 *===========================================================================
 *                         ipcrypto_cmd_cmp
 *===========================================================================
 */
IP_PUBLIC int
ipcrypto_cmd_cmp(int argc, char **argv)
{
  struct Ip_stat sb1, sb2;
  Ip_off_t skip1, skip2;
  int ch, fd1, fd2, special;
  char *file1, *file2;

  ipcom_getopt_clear();
  lflag = 0;
  sflag = 0;

  while ((ch = ipcom_getopt(argc, argv, "ls")) != -1)
    switch (ch) {
    case 'l':		/* print all differences */
      lflag = 1;
      break;
    case 's':		/* silent run */
      sflag = 1;
      break;
    case '?':
    default:
      usage();
    }
  argv += ip_optind;
  argc -= ip_optind;

  if (lflag && sflag)
    errx(ERR_EXIT, "only one of -l and -s may be specified");

  if (argc < 2 || argc > 4)
    usage();

  /* Backward compatibility -- handle "-" meaning stdin. */
  special = 0;
  if (ipcom_strcmp(file1 = argv[0], "-") == 0) {
    special = 1;
    fd1 = 0;
    file1 = "stdin";
  }
  else if ((fd1 = ipcom_fileopen(file1, IP_O_RDONLY, 0)) < 0) {
    if (!sflag)
      errx(ERR_EXIT, "%s", file1);
    else
      ipcom_exit(1);
  }
  if (ipcom_strcmp(file2 = argv[1], "-") == 0) {
    if (special)
      errx(ERR_EXIT,
	   "standard input may only be specified once");
    special = 1;
    fd2 = 0;
    file2 = "stdin";
  }
  else if ((fd2 = ipcom_fileopen(file2, IP_O_RDONLY, 0)) < 0) {
    if (!sflag)
      errx(ERR_EXIT, "%s", file2);
    else
      ipcom_exit(1);
  }

  skip1 = argc > 2 ? ipcom_atol(argv[2]) : 0;
  skip2 = argc == 4 ? ipcom_atol(argv[3]) : 0;

  if (!special) {
    if (ipcom_fstat(fd1, &sb1)) {
      if (!sflag)
	errx(ERR_EXIT, "%s", file1);
      else
	ipcom_exit(1);
    }
    if (!IP_S_ISREG(sb1.st_mode))
      special = 1;
    else {
      if (ipcom_fstat(fd2, &sb2)) {
	if (!sflag)
	  errx(ERR_EXIT, "%s", file2);
	else
	  ipcom_exit(1);
      }
      if (!IP_S_ISREG(sb2.st_mode))
	special = 1;
    }
  }

  c_special(fd1, file1, skip1, fd2, file2, skip2);
  ipcom_exit(0);
  return 0;  /* will never get here. */
}


/*
 *===========================================================================
 *                         usage
 *===========================================================================
 */
static void
usage(void)
{
  (void)ipcom_fprintf(ip_stderr,
		"usage: cmp [-l | -s] file1 file2 [skip1 [skip2]]"IP_LF);
  ipcom_exit(ERR_EXIT);
}


/*
 *===========================================================================
 *                         eofmsg
 *===========================================================================
 * from misc.c
 */
static void
eofmsg(char *file)
{
    if (!sflag)
    {
        (void)ipcom_fprintf(ip_stderr, "%s: ", __progname);
        ipcom_fprintf(ip_stderr, "EOF on %s, file"IP_LF, file);
    }
    ipcom_exit(DIFF_EXIT);
}


/*
 *===========================================================================
 *                         diffmsg
 *===========================================================================
 * from misc.c
 */
static void
diffmsg(char *file1, char *file2, Ip_off_t byte, Ip_off_t line)
{
  if (!sflag)
      (void)ipcom_printf("%s %s differ: char %d, line %d"IP_LF,
                         file1, file2, (int)byte, (int)line);
  ipcom_exit(DIFF_EXIT);
}


/*
 *===========================================================================
 *                         c_special
 *===========================================================================
 * from special.c
 */
static void
c_special(int fd1, char *file1, Ip_off_t skip1, int fd2, char *file2, Ip_off_t skip2)
{
  int ch1, ch2;
  Ip_off_t byte, line;
  IP_FILE *fp1, *fp2;
  int dfound;

  if ((fp1 = ipcom_fdopen(fd1, "r")) == IP_NULL)
    errx(ERR_EXIT, "%s", file1);
  if ((fp2 = ipcom_fdopen(fd2, "r")) == IP_NULL)
    errx(ERR_EXIT, "%s", file2);

  dfound = 0;
  while (skip1--)
    if (ipcom_getc(fp1) == IP_EOF)
      goto eof;
  while (skip2--)
    if (ipcom_getc(fp2) == IP_EOF)
      goto eof;

  for (byte = line = 1;; ++byte) {
    ch1 = ipcom_getc(fp1);
    ch2 = ipcom_getc(fp2);
    if (ch1 == IP_EOF || ch2 == IP_EOF)
      break;
    if (ch1 != ch2)
      {
	if (lflag) {
	  dfound = 1;
	  (void)ipcom_printf("%6d %3o %3o"IP_LF, (int)byte, ch1, ch2);
	} else
	  diffmsg(file1, file2, byte, line);
      }
				/* NOTREACHED */
    if (ch1 == '\n')
      ++line;
  }

 eof:
  if(ipcom_ferror(fp1))
    errx(ERR_EXIT, "%s", file1);
  if (ipcom_ferror(fp2))
    errx(ERR_EXIT, "%s", file2);
  if (ipcom_feof(fp1)) {
    if (!ipcom_feof(fp2))
      eofmsg(file1);
  } else
    if (ipcom_feof(fp2))
      eofmsg(file2);
  if (dfound)
    ipcom_exit(DIFF_EXIT);
}


/*
 ****************************************************************************
 * END OF FILE
 ****************************************************************************
 */

