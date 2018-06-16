/** \file
 * This file contains interface definitions for the ISOidentity
 * modelling enclave.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Number of enclave interfaces. */
#define ECALL_NUMBER 2
#define OCALL_NUMBER 5


/* ECALL interface definitions. */
struct ISOmanager_ecall0 {
	_Bool retn;
	_Bool debug_mode;

	time_t current_time;

	int port;

	char *hostname;
	size_t hostname_size;

	char *spid;
	size_t spid_size;

	unsigned char *identity;
	size_t identity_size;

	unsigned char *verifier;
	size_t verifier_size;
};

struct ISOmanager_ecall1 {
	_Bool retn;

	uint8_t id[32];
};

