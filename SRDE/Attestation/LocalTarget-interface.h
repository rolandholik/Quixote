/** \file
 * This file contains interface definitions for the LocalTarget enclave.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* ECALL interface definitions. */
struct LocalTarget_ecall0_interface {
	_Bool retn;
	unsigned int mode;
	struct SGX_targetinfo *target;
	struct SGX_report *report;
};

/* ECALL interface definitions. */
struct LocalTarget_ecall1 {
	_Bool retn;
	_Bool apikey;
	_Bool development;
	_Bool nonce;
	_Bool full_report;

	size_t qe_token_size;
	char *qe_token;

	size_t pce_token_size;
	char *pce_token;

	size_t epid_blob_size;
	char *epid_blob;

	size_t spid_size;
	char *spid;

	char key[33];
};


struct LocalTarget_ecall3 {
	_Bool retn;
};
