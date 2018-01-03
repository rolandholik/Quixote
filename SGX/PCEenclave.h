/** \file
 * This file contains definitions for an object which implements
 * management of the Intel PCE enclave.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

#ifndef NAAAIM_PCEenclave_HEADER
#define NAAAIM_PCEenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_PCEenclave * PCEenclave;

typedef struct NAAAIM_PCEenclave_State * PCEenclave_State;

/**
 * External PCEenclave object representation.
 */
struct NAAAIM_PCEenclave
{
	/* External methods. */
	_Bool (*open)(const PCEenclave, const char *);

	void (*get_target_info)(const PCEenclave, struct SGX_targetinfo *);

	_Bool (*get_info)(const PCEenclave, struct SGX_pek *, \
			  struct SGX_report *);

	void (*dump)(const PCEenclave);
	void (*whack)(const PCEenclave);


	/* Private state. */
	PCEenclave_State state;
};


/* Sgxmetadata constructor call. */
extern PCEenclave NAAAIM_PCEenclave_Init(void);
#endif
