/** \file
 * This file contains shim code which is used to minimize the changes
 * needed to the HurdLib code in order to make it compatible with
 * the limited execution environment provided in an enclave environment.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

#include <sys/limits.h>

#include <SRDEfusion-ocall.h>

#include "fusion-shim.h"


/**
 * External function.
 *
 * This function implements a replacement for the sprintf function that
 * is not included in the Intel SDK.  The strategy used is similar to
 * what is implemented in the MUSL C library, obviously a dangerous
 * proposition.
 *
 * \param bufr		A pointer to the buffer which the formatted
 *			string will be written to.
 *
 * \param format	A pointer to a null-terminated buffer containing
 *			the formatting string to be used for printing
 *			to the aforementioned buffer.
 *
 * \return		This function returns the value returned by
 *			the vsnprintf library function which is the
 *			number of characters written to the output
 *			buffer not including the null character.
 */

int sprintf(char *bufr, const char *fmt, ...)

{
	size_t cnt;

	va_list ap;


	va_start(ap, fmt);
	cnt = vsnprintf(bufr, INT_MAX, fmt, ap);
	va_end(ap);

	return cnt;
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
 * Alternate fprintf implementation that prints the formatted output
 * to a buffer with subsequent output of the buffer via an OCALL to
 * untrusted userspace to be printed to the specified stream
 * descriptor.
 */

void fprintf(int stream, const char *fmt, ...)

{
	int size;

	char bufr[BUFSIZ];

	char *mb = NULL,
	     *pb = bufr;

	va_list ap;


	/* Compute and configure the needed buffer size. */
	va_start(ap, fmt);
	size = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if ( size <= sizeof(bufr) )
		size = sizeof(bufr);
	else {
		if ( (mb = malloc(size)) != NULL )
			pb = mb;
	}
	memset(pb, size, '\0');


	/* Print and output the buffer. */
	va_start(ap, fmt);
	vsnprintf(pb, size, fmt, ap);
	va_end(ap);

	ocall_print_string(pb);


	free(mb);
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

	size_t arena_size = sizeof(struct SRDEfusion_ocall1_interface) + \
		bufr_size;

	struct SRDEfusion_ocall1_interface *op = NULL;


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
	if ( (status = sgx_ocall(SRDEFUSION_OCALL1, op)) != 0 )
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

	struct SRDEfusion_ocall0_interface *ms = NULL;

	size_t ocalloc_size = sizeof(struct SRDEfusion_ocall0_interface);

	void *__tmp = NULL;


	ocalloc_size += (str != NULL && \
			 sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (struct SRDEfusion_ocall0_interface *) __tmp;
	__tmp = (void *) ((size_t)__tmp + \
			  sizeof(struct SRDEfusion_ocall0_interface));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->buffer = (char*) __tmp;
		__tmp = (void *) ((size_t)__tmp + _len_str);
		memcpy((void *) ms->buffer, str, _len_str);
	} else if (str == NULL) {
		ms->buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}

	status = sgx_ocall(SRDEFUSION_OCALL0, ms);


	sgx_ocfree();
	return status;
}
