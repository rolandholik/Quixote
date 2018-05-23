/** \file
 * This file contains shim code which is used to minimize the changes
 * needed to the HurdLib code in order to make it compatible with
 * the limited execution environment provided in an enclave environment.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

#include "fusion-shim.h"


/* Stub function for registering exit handler. */
int atexit(void (*function)(void))

{
	return 0;
}


/*
 * Alternate printf implementation which uses an OCALL to print
 * to the standard output of the process invoking the enclave.
 */

void printf(const char *fmt, ...)

{
	char bufr[1024];


	memset(bufr, '\0', sizeof(bufr));

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(bufr, BUFSIZ, fmt, ap);
	va_end(ap);

	ocall_print_string(bufr);
	return;
}


/*
 * Alternate fprintf implementation which uses an OCALL to print
 * to the standard output of the process invoking the enclave.
 */

void fprintf(int stream, const char *fmt, ...)

{
    char bufr[1024];


    memset(bufr, '\0', sizeof(bufr));

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(bufr, sizeof(bufr), fmt, ap);
    va_end(ap);

    ocall_print_string(bufr);
    return;
}


/*
 * Alternate fputc implementation which uses the fprintf function
 * to generate output through an OCALL.
 */
void fputc(char inchar, int stream)

{
	fprintf(stream, "%c", inchar);
	return;
}


/*
 * Alternate fputc implementation which uses the fprintf function
 * to generate output through an OCALL.
 */
void fputs(const char *bufr, int stream)

{
	fprintf(stream, "%s", bufr);
	return;
}


/*
 * An implementation of fgets which uses an OCALL to request services
 * from the fgets function in untrusted space.
 */
char *fgets(char *bufr, int bufr_size, int stream)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	size_t arena_size = sizeof(struct SGXfusion_fgets_interface) + \
		bufr_size;

	struct SGXfusion_fgets_interface *op = NULL;


	/* Verify arguements and set size of arena. */
	if ( !sgx_is_within_enclave(bufr, bufr_size) )
		goto done;

	/* Allocate and initialize the interface structure. */
	if ( (op = sgx_ocalloc(arena_size)) == NULL )
		goto done;
	memset(op, '\0', arena_size);

	op->stream    = stream;
	op->bufr_size = bufr_size;


	/* Call the user handler slot. */
	if ( (status = sgx_ocall(1, op)) != 0 )
		goto done;

	if ( op->retn ) {
		retn = true;
		memcpy(bufr, op->bufr, bufr_size);
	}


 done:
	if ( op != NULL )
		memset(op, '\0', arena_size);
	sgx_ocfree();

	if ( status != 0 ) {
		fprintf(stdout, "%s: error=%d\n", __func__, status);
		return NULL;
	}
	if ( !retn )
		return NULL;
	return bufr;
}


/*
 * This function implements the OCALL which exports a formatted buffer
 * to untrusted space to be printed.
 */
sgx_status_t ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;

	size_t _len_str = str ? strlen(str) + 1 : 0;

	struct SGXfusion_ocall0_interface *ms = NULL;

	size_t ocalloc_size = sizeof(struct SGXfusion_ocall0_interface);

	void *__tmp = NULL;


	ocalloc_size += (str != NULL && \
			 sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (struct SGXfusion_ocall0_interface *) __tmp;
	__tmp = (void *) ((size_t)__tmp + \
			  sizeof(struct SGXfusion_ocall0_interface));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->bufr = (char*) __tmp;
		__tmp = (void *) ((size_t)__tmp + _len_str);
		memcpy((void *) ms->bufr, str, _len_str);
	} else if (str == NULL) {
		ms->bufr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}

	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}
