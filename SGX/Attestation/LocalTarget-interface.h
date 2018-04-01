/** \file
 * This file contains interface definitions for the LocalTarget enclave.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Number of enclave interfaces. */
#define ECALL_NUMBER 2
#define OCALL_NUMBER 4


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

	size_t qe_token_size;
	char *qe_token;

	size_t pce_token_size;
	char *pce_token;

	size_t epid_blob_size;
	char *epid_blob;

	size_t spid_size;
	char *spid;
};
