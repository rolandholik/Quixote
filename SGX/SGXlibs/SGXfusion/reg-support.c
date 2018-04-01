/** \file
 * This file contains support routines for the regular expression
 * functions.  This code is abstracted from the musl C library from
 * which the regular expression routines were abstracted.
 */

#define WCTYPE_ALNUM  1
#define WCTYPE_ALPHA  2
#define WCTYPE_BLANK  3
#define WCTYPE_CNTRL  4
#define WCTYPE_DIGIT  5
#define WCTYPE_GRAPH  6
#define WCTYPE_LOWER  7
#define WCTYPE_PRINT  8
#define WCTYPE_PUNCT  9
#define WCTYPE_SPACE  10
#define WCTYPE_UPPER  11
#define WCTYPE_XDIGIT 12


#include <string.h>
#include <wctype.h>
#include <ctype.h>

#include "reg-support.h"


wctype_t wctype(const char *s)
{
	int i;
	const char *p;
	/* order must match! */
	static const char names[] =
		"alnum\0" "alpha\0" "blank\0"
		"cntrl\0" "digit\0" "graph\0"
		"lower\0" "print\0" "punct\0"
		"space\0" "upper\0" "xdigit";
	for (i=1, p=names; *p; i++, p+=6)
		if (*s == *p && !strcmp(s, p))
			return i;
	return 0;
}


int iswctype(wint_t wc, wctype_t type)
{
	switch (type) {
	case WCTYPE_ALNUM:
		return isalnum(wc);
	case WCTYPE_ALPHA:
		return isalpha(wc);
	case WCTYPE_BLANK:
		return isblank(wc);
	case WCTYPE_CNTRL:
		return iscntrl(wc);
	case WCTYPE_DIGIT:
		return isdigit(wc);
	case WCTYPE_GRAPH:
		return isgraph(wc);
	case WCTYPE_LOWER:
		return islower(wc);
	case WCTYPE_PRINT:
		return isprint(wc);
	case WCTYPE_PUNCT:
		return ispunct(wc);
	case WCTYPE_SPACE:
		return isspace(wc);
	case WCTYPE_UPPER:
		return isupper(wc);
	case WCTYPE_XDIGIT:
		return isxdigit(wc);
	}
	return 0;
}
