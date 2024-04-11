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
#define ECALL_NUMBER 2
#define OCALL_NUMBER 4


/* ECALL interface definitions. */
struct Duct_ecall0 {
	_Bool retn;

	int port;
};

struct Duct_ecall1 {
	_Bool retn;

	int port;
	char *hostname;
	size_t hostname_size;
};


_Bool test_server(unsigned int);
_Bool test_client(char *, int port);
#endif
