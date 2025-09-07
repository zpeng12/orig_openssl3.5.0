

#ifdef CPU
#include <sys/types.h>
#define FAST
#include <errno.h>

#if 0
#include <vxWorks.h>
#include <limits.h>
#include <ctype.h>
#include <stdlib.h>
#endif

/* diab doesn't define these limits... */
#if(TOOL==diab)

#ifndef __LONG_LONG_MAX__
#define __LONG_LONG_MAX__ 9223372036854775807LL
#endif

#undef LONG_LONG_MIN
#define LONG_LONG_MIN (-LONG_LONG_MAX-1)
#undef LONG_LONG_MAX
#define LONG_LONG_MAX __LONG_LONG_MAX__
#endif

#else

#define FAST
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

#ifndef __LONG_LONG_MAX__
#define __LONG_LONG_MAX__ 9223372036854775807LL
#endif
#undef LONG_LONG_MIN
#define LONG_LONG_MIN (-LONG_LONG_MAX-1)
#undef LONG_LONG_MAX
#define LONG_LONG_MAX __LONG_LONG_MAX__

#endif

long long strtoimax
    (
    const char * nptr,		/* string to convert */
    char **      endptr,	/* ptr to final string */
    FAST int     base		/* radix */
    )
    {
    FAST const                  char *s = nptr;
    FAST unsigned long long     acc;
    FAST int 	                c;
    FAST unsigned long long     cutoff;
    FAST int                    neg = 0;
    FAST int                    any;
    FAST int                    cutlim;

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    do 
        {
    	c = *s++;
        } while (isspace (c));

    if (c == '-') 
        {
    	neg = 1;
    	c = *s++;
        } 
    else if (c == '+')
    	c = *s++;

    if (((base == 0) || (base == 16)) &&
        (c == '0') && 
        ((*s == 'x') || (*s == 'X'))) 
        {
    	c = s[1];
    	s += 2;
    	base = 16;
        }

    if (base == 0)
    	base = (c == '0' ? 8 : 10);

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for longs is
     * [-2147483648..2147483647] and the input base is 10,
     * cutoff will be set to 214748364 and cutlim to either
     * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
     * a value > 214748364, or equal but the next digit is > 7 (or 8),
     * the number is too big, and we will return a range error.
     *
     * Set any if any `digits' consumed; make it negative to indicate
     * overflow.
     */

    cutoff = (neg ? -(unsigned long long) LONG_LONG_MIN : LONG_LONG_MAX);
    cutlim = (int)(cutoff % base);
    cutoff /= (unsigned long long) base;

    for (acc = 0, any = 0;; c = *s++) 
        {
    	if (isdigit (c))
    	    c -= '0';
    	else if (isalpha (c))
    	    c -= (isupper(c) ? 'A' - 10 : 'a' - 10);
    	else
    	    break;

    	if (c >= base)
    	    break;

    	if ((any < 0) || (acc > cutoff) || ((acc == cutoff) && (c > cutlim)))
    	    any = -1;
    	else 
            {
    	    any = 1;
    	    acc *= base;
    	    acc += c;
    	    }
        }

    if (any < 0) 
        {
    	acc = (neg ? LONG_LONG_MIN : LONG_LONG_MAX);
    	errno = ERANGE;
        } 
    else if (neg)
    	acc = -acc;

    if (endptr != 0)
    	*endptr = (any ? (char *) (s - 1) : (char *) nptr);

    return (acc);
    }


#if defined(_MSC_VER) || defined(__WATCOMC__)
#define MYMIN 0x8000000000000000i64
#define MYMAX 0x7FFFFFFFFFFFFFFFi64
#elif defined(HAVE_LL)
#define MYMIN 0x8000000000000000LL
#define MYMAX 0x7FFFFFFFFFFFFFFFLL
#else
#define MYMIN 0x8000000000000000L
#define MYMAX 0x7FFFFFFFFFFFFFFFL
#endif

unsigned long long (strtoumax)(const char * s, char ** endptr, int base)
{	/* convert string to long long, with checking */
	const char *sc;
	char *se, sign;
	unsigned long long x;

	if (endptr == 0)
		endptr = &se;
	for (sc = s; isspace((unsigned char)*sc); ++sc)
		;
	sign = (char)(*sc == '-' || *sc == '+' ? *sc++ : '+');
	x = _Stoull(sc, endptr, base);
	if (sc == *endptr)
		*endptr = (char *)s;
	if (s == *endptr && x != 0 || sign == '+' && MYMAX < x
		|| sign == '-' && 0 - (unsigned long long)MYMIN < x)
		{	/* overflow */
		errno = ERANGE;
		return (sign == '-' ? MYMIN : MYMAX);
		}
	else
		return ((unsigned long long)(sign == '-' ? 0 - x : x));
}


#if 0

unsigned long long (strtoumax)(const char *_Restrict s, char **_Restrict endptr, int base)
	{	/* convert string to uintmax_t, with checking */
	return (_Stoull(s, endptr, base));
	}
#endif	
