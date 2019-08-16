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
time_t time(time_t *);


/* Prototype for the OCALL used to implement the *printf functions. */
struct SRDEfusion_ocall0_interface {
	char *bufr;
};

struct SRDEfusion_fgets_interface {
	_Bool retn;

	int stream;
	char bufr_size;
	char bufr[];
};

sgx_status_t ocall_print_string(const char* str);


/*
 * In order to make fprintf work declare integers for stderr and
 * stdout.
 */
#define stdout 1
#define stderr 2
#define stdin  3

void printf(const char *, ...);
void fputs(const char *, int);
void fputc(char, int);
void fprintf(int, const char *, ...);

char *fgets(char *, int, int);
