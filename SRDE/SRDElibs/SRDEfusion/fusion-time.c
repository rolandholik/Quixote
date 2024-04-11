/** \file
 * This file contains code that implements various time related
 * functionality from the standard C library in order to minimize the
 * amount of changes needed to make enclave based applications
 * compatible with standard userspace.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include "fusion-shim.h"


/* Definitions for the language constants used in the strptime function. */
#define ABDAY_1 0x20000
#define ABDAY_2 0x20001
#define ABDAY_3 0x20002
#define ABDAY_4 0x20003
#define ABDAY_5 0x20004
#define ABDAY_6 0x20005
#define ABDAY_7 0x20006

#define ABMON_1	 0x2000E
#define ABMON_2	 0x2000F
#define ABMON_3	 0x20010
#define ABMON_4	 0x20011
#define ABMON_5  0x20012
#define ABMON_6	 0x20013
#define ABMON_7	 0x20014
#define ABMON_8	 0x20015
#define ABMON_9	 0x20016
#define ABMON_10 0x20017
#define ABMON_11 0x20018
#define ABMON_12 0x20019


/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <time.h>

#include <sys/limits.h>


/**
 * External function.
 *
 * This function implements a replacement for the strptime function
 * that is not included in the Intel SDK.  The implementation is from
 * the MUSL C library along with the definitions for the language
 * constants.
 *
 * \param s	A character pointer to a null terminated buffer
 *`		containing the source string that will be decoded
 *		into the time definition structure.
 *
 * \param f	A pointer to a null-terminated buffer containing the
 *		formatting string to be used to interpret the
 *		source buffer.
 *
 * \param tm	A pointer to the structure which will be populated
 *		with the interpreted time.
 *
 * \return	The return value is a pointer to the first character
 *		in the source buffer that is not interpreted.
 */

char *strptime(const char *s, const char *f, struct tm *tm)
{
	int i, w, neg, adj, min, range, *dest, dummy;
	const char *ex;
	size_t len;
	int want_century = 0, century = 0, relyear = 0;
	while (*f) {
		if (*f != '%') {
			if (isspace(*f)) for (; *s && isspace(*s); s++);
			else if (*s != *f) return 0;
			else s++;
			f++;
			continue;
		}
		f++;
		if (*f == '+') f++;
		if (isdigit(*f)) {
			char *new_f;
			w=strtoul(f, &new_f, 10);
			f = new_f;
		} else {
			w=-1;
		}
		adj=0;
		switch (*f++) {
		case 'a': case 'A':
			dest = &tm->tm_wday;
			min = ABDAY_1;
			range = 7;
			goto symbolic_range;
		case 'b': case 'B': case 'h':
			dest = &tm->tm_mon;
			min = ABMON_1;
			range = 12;
			goto symbolic_range;
		case 'c':
			s = strptime(s, "%a %b %e %T %Y", tm);
			if (!s) return 0;
			break;
		case 'C':
			dest = &century;
			if (w<0) w=2;
			want_century |= 2;
			goto numeric_digits;
		case 'd': case 'e':
			dest = &tm->tm_mday;
			min = 1;
			range = 31;
			goto numeric_range;
		case 'D':
			s = strptime(s, "%m/%d/%y", tm);
			if (!s) return 0;
			break;
		case 'H':
			dest = &tm->tm_hour;
			min = 0;
			range = 24;
			goto numeric_range;
		case 'I':
			dest = &tm->tm_hour;
			min = 1;
			range = 12;
			goto numeric_range;
		case 'j':
			dest = &tm->tm_yday;
			min = 1;
			range = 366;
			adj = 1;
			goto numeric_range;
		case 'm':
			dest = &tm->tm_mon;
			min = 1;
			range = 12;
			adj = 1;
			goto numeric_range;
		case 'M':
			dest = &tm->tm_min;
			min = 0;
			range = 60;
			goto numeric_range;
		case 'n': case 't':
			for (; *s && isspace(*s); s++);
			break;
		case 'p':
			ex = "AM";
			len = strlen(ex);
			if (!strncasecmp(s, ex, len)) {
				tm->tm_hour %= 12;
				s += len;
				break;
			}
			ex = "PM";
			len = strlen(ex);
			if (!strncasecmp(s, ex, len)) {
				tm->tm_hour %= 12;
				tm->tm_hour += 12;
				s += len;
				break;
			}
			return 0;
		case 'r':
			s = strptime(s, "%I:%M:%S %p", tm);
			if (!s) return 0;
			break;
		case 'R':
			s = strptime(s, "%H:%M", tm);
			if (!s) return 0;
			break;
		case 'S':
			dest = &tm->tm_sec;
			min = 0;
			range = 61;
			goto numeric_range;
		case 'T':
			s = strptime(s, "%H:%M:%S", tm);
			if (!s) return 0;
			break;
		case 'U':
		case 'W':
			/* Throw away result, for now. (FIXME?) */
			dest = &dummy;
			min = 0;
			range = 54;
			goto numeric_range;
		case 'w':
			dest = &tm->tm_wday;
			min = 0;
			range = 7;
			goto numeric_range;
		case 'x':
			s = strptime(s, "%m/%d/%y", tm);
			if (!s) return 0;
			break;
		case 'X':
			s = strptime(s, "%H:%M:%S", tm);
			if (!s) return 0;
			break;
		case 'y':
			dest = &relyear;
			w = 2;
			want_century |= 1;
			goto numeric_digits;
		case 'Y':
			dest = &tm->tm_year;
			if (w<0) w=4;
			adj = 1900;
			want_century = 0;
			goto numeric_digits;
		case '%':
			if (*s++ != '%') return 0;
			break;
		default:
			return 0;
		numeric_range:
			if (!isdigit(*s)) return 0;
			*dest = 0;
			for (i=1; i<=min+range && isdigit(*s); i*=10)
				*dest = *dest * 10 + *s++ - '0';
			if (*dest - min >= (unsigned)range) return 0;
			*dest -= adj;
			switch((char *)dest - (char *)tm) {
			case offsetof(struct tm, tm_yday):
				;
			}
			goto update;
		numeric_digits:
			neg = 0;
			if (*s == '+') s++;
			else if (*s == '-') neg=1, s++;
			if (!isdigit(*s)) return 0;
			for (*dest=i=0; i<w && isdigit(*s); i++)
				*dest = *dest * 10 + *s++ - '0';
			if (neg) *dest = -*dest;
			*dest -= adj;
			goto update;
		symbolic_range:
			for (i=2*range-1; i>=0; i--) {
				ex = "\0";
				len = strlen(ex);
				if (strncasecmp(s, ex, len)) continue;
				s += len;
				*dest = i % range;
				break;
			}
			if (i<0) return 0;
			goto update;
		update:
			//FIXME
			;
		}
	}
	if (want_century) {
		tm->tm_year = relyear;
		if (want_century & 2) tm->tm_year += century * 100 - 1900;
		else if (tm->tm_year <= 68) tm->tm_year += 100;
	}
	return (char *)s;
}


/**
 * External function.
 *
 * This function implements a replacement for the mktime function
 * that is not included in the Intel SDK.  This function currently
 * zeros the time structure that is passed to it.
 *
 * \param s	A character pointer to a null terminated buffer
 *`		containing the source string that will be decoded
 *		into the time definition structure.
 *
 * \return	The return value is a pointer to the first character
 *		in the source buffer that is not interpreted.
 */

time_t mktime(struct tm *tm)

{
	memset(tm, '\0', sizeof(struct tm));
	return 0;
}


/**
 * External function.
 *
 * This function implements a replacement for the gettimeofday function
 * that is not included in the Intel SDK.  This function currently
 * returns a structure will all elements set to zero.
 *
 * \param tm	A pointer to the structure that will be loaded with
 *		the current time.
 *
 * \param tz	A pointer to the structure that will be loaded with
 *		the current timezone.
 *
 * \return	A return value of 0 is returned to indicate the call
 *		was successful while a value of -1 indicates an
 *		error condition although no error conditions are
 *		currently supported.
 */

int gettimeofday(struct timeval *tm, struct timezone *tz)

{
	tm->tv_sec = 0;
	tm->tv_usec = 0;

	return 0;
}


/**
 * External function.
 *
 * This function implements a replacement for the gmtime_r function
 * that is not included in the Intel SDK.  This function currently
 * returns structures that have all elements set to zero.
 *
 * \param timep	A pointer to the structure that will be loaded with
 *		the current time.
 *
 * \param tm	A pointer to the structure that will be loaded with
 *		the current broken out time.
 *
 * \return	Error returns are not supported but if an error
 *		were to be returned a NULL value would be returned
 *		to the caller.  A successful return returns a
 *		pointer to a structure describing the broken out
 *		time.
 */

struct tm *gmtime_r(time_t *timep, struct tm *tm)

{
	*timep = 0;

	tm->tm_sec   = 0;
	tm->tm_min   = 0;
	tm->tm_hour  = 0;
	tm->tm_mday  = 0;
	tm->tm_mon   = 0;
	tm->tm_year  = 70;
	tm->tm_wday  = 0;
	tm->tm_yday  = 0;
	tm->tm_isdst = 0;

	return tm;
}


/**
 * External function.
 *
 * This function implements a replacement for the localtime_r function
 * that is not included in the Intel SDK.  This function currently
 * returns structures that have all elements set to zero.
 *
 * \param timep	A pointer to the structure that will be loaded with
 *		the current time.
 *
 * \param tm	A pointer to the structure that will be loaded with
 *		the current broken out time.
 *
 * \return	Error returns are not supported but if an error
 *		were to be returned a NULL value would be returned
 *		to the caller.  A successful return returns a
 *		pointer to a structure describing the broken out
 *		time.
 */

struct tm *localtime_r(time_t *timep, struct tm *tm)

{
	*timep = 0;

	tm->tm_sec   = 0;
	tm->tm_min   = 0;
	tm->tm_hour  = 0;
	tm->tm_mday  = 1;
	tm->tm_mon   = 0;
	tm->tm_year  = 70;
	tm->tm_wday  = 0;
	tm->tm_yday  = 0;
	tm->tm_isdst = 0;

	return tm;
}
