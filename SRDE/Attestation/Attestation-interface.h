/** \file
 * This file contains interface definitions for the Attestation enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Number of enclave interfaces. */
#define ECALL_NUMBER 2
#define OCALL_NUMBER SRDENAAAIM_MAX_OCALL+1


/* ECALL 0 interface definitions. */
struct Attestation_ecall0 {
	_Bool retn;

	time_t current_time;

	size_t key_size;
	unsigned char *key;
};
