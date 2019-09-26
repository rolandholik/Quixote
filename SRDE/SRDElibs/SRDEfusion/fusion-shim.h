/** \file
 * This file contains header definitions for the shim code which is
 * used to maintain compatibility from the native HurdLib code to
 * the enclave limited version of the library.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Enclave SDK include files. */
#include <sgx_edger8r.h>
#include <sgx_trts.h>
#include <time.h>

typedef int pid_t;


/* Prototypes for alternate standard library functions. */

sgx_status_t ocall_print_string(const char* str);


/*
 * Declarations for functionality from fusion-time.c
 */
typedef long suseconds_t;

struct timeval {
	time_t tv_sec;
	suseconds_t tv_usec;
};

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

time_t time(time_t *);
time_t mktime(struct tm *tm);
char *strptime(const char *, const char *, struct tm *);
int gettimeofday(struct timeval *, struct timezone *);
struct tm *gmtime_r(time_t *, struct tm *);
struct tm *localtime_r(time_t *, struct tm *);


/*
 * In order to make fprintf work declare integers for stderr and
 * stdout.
 */
#define stdout 1
#define stderr 2
#define stdin  3

int sprintf(char *bufr, const char *, ...);
void printf(const char *, ...);
void fputs(const char *, int);
void fputc(char, int);
void fprintf(int, const char *, ...);

char *fgets(char *, int, int);
