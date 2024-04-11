/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <stdlib.h>


/* Number of enclave interfaces. */
#define ECALL_NUMBER 3
#define OCALL_NUMBER 6


/* ECALL interface definitions. */
struct Possum2_ecall0 {
	_Bool retn;
	_Bool debug_mode;

	time_t current_time;

	int port;

	char *spid;
	size_t spid_size;
};

struct Possum2_ecall1 {
	_Bool retn;
	_Bool debug_mode;

	time_t current_time;

	int port;

	char *hostname;
	size_t hostname_size;

	unsigned char *key;
	size_t key_size;
};

struct Possum2_ecall2 {
	_Bool retn;

	uint8_t *key;
	size_t key_size;
};


_Bool test_server(struct Possum2_ecall0 *);
_Bool test_client(struct Possum2_ecall1 *);
_Bool add_verifier(struct Possum2_ecall2 *);
#endif
