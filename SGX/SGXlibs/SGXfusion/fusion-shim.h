/** \file
 * This file contains header definitions for the shim code which is
 * used to maintain compatibility from the native HurdLib code to
 * the enclave limited version of the library.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Enclave SDK include files. */
#include <sgx_edger8r.h>
#include <sgx_trts.h>


/* Prototypes for alternate standard library functions. */
int atexit(void (*function)(void));


/* Prototype for the OCALL used to implement the *printf functions. */
struct SGXfusion_ocall0_interface {
	char *bufr;
};

sgx_status_t ocall_print_string(const char* str);


/*
 * In order to make fprintf work declare integers for stderr and
 * stdout.
 */
#define stdout 1
#define stderr 2

void printf(const char *, ...);
void fputs(const char *, int);
void fputc(char, int);
void fprintf(int, const char *, ...);
