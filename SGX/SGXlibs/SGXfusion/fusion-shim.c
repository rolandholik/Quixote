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
