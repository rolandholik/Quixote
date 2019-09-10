/** \file
 * This file contains interface definitions for the OCALL's that
 * are used by the SRDEfusion enclave library.
 *
 * This file is designed to be included by code from both untrusted
 * and enclave space.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions of the OCALL function slots. */
#define SRDEFUSION_OCALL0	0
#define SRDEFUSION_OCALL1	1
#define SRDEFUSION_OCALL2	2

#define SRDEFUSION_MAX_OCALL	SRDEFUSION_OCALL2


/**
 * This structure defines the interface used by SRDEFUSION_OCALL0 to
 * pass a formated buffer to untrusted space for output.
 */
struct SRDEfusion_ocall0_interface {
	char *buffer;
};


/**
 * This structure defines the interface used by SRDEFUSION_OCALL1 to
 * read input from untrusted space and return it to enclave context.
 */
struct SRDEfusion_ocall1_interface {
	_Bool retn;

	int stream;
	char bufr_size;
	char bufr[];
};
