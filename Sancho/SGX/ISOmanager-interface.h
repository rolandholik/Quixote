/** \file
 * This file contains interface definitions for the ISOidentity
 * modelling enclave.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Number of enclave interfaces. */
#define ECALL_NUMBER 3
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
};

struct ISOmanager_ecall1 {
	_Bool retn;

	uint8_t id[32];
};

struct ISOmanager_ecall2 {
	_Bool retn;

	uint8_t *verifier;
	size_t verifier_size;
};
