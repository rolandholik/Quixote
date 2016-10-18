/** \file
 * This file contains definitions for an object which the management
 * of a Software Guard Extension (SGX) enclave.
 */

/**************************************************************************
 * (C)Copyright 2016, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_SGXenclave_HEADER
#define NAAAIM_SGXenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXenclave * SGXenclave;

typedef struct NAAAIM_SGXenclave_State * SGXenclave_State;

/**
 * External SGXenclave object representation.
 */
struct NAAAIM_SGXenclave
{
	/* External methods. */
	_Bool (*open_enclave)(const SGXenclave, const char *, const char *, \
			      _Bool);
	_Bool (*create_enclave)(const SGXenclave);

	void (*whack)(const SGXenclave);

	/* Private state. */
	SGXenclave_State state;
};


/* Sgxmetadata constructor call. */
extern SGXenclave NAAAIM_SGXenclave_Init(void);

#endif
