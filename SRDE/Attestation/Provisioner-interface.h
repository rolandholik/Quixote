/** \file
 * This file contains interface definitions for the Provisioner enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Number of enclave interfaces. */
#define ECALL_NUMBER 3
#define OCALL_NUMBER SRDENAAAIM_MAX_OCALL+1


/** Provisioner ECALL 0 interface definition. */
struct Provisioner_ecall0 {
	_Bool retn;

	size_t key_size;
	char *key;
};


/** Provisioner ECALL 1 interface definition. */
struct Provisioner_ecall1 {
	_Bool retn;

	time_t current_time;

	char spid[33];
	char apikey[33];
};
