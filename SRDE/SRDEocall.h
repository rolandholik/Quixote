/** \file
 * This file contains the external definition for an object that
 * manages the OCALL definitions for an enclave.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEocall_HEADER
#define NAAAIM_SRDEocall_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEocall * SRDEocall;

typedef struct NAAAIM_SRDEocall_State * SRDEocall_State;

/**
 * External SRDEocall object representation.
 */
struct NAAAIM_SRDEocall
{
	/* External methods. */
	_Bool (*add)(const SRDEocall, const void *);
	_Bool (*add_table)(const SRDEocall, const void **);

	_Bool (*get_table)(const SRDEocall, struct OCALL_api **);

	void (*print)(const SRDEocall);
	void (*whack)(const SRDEocall);

	/* Private state. */
	SRDEocall_State state;
};


/* SRDEocall constructor call. */
extern HCLINK SRDEocall NAAAIM_SRDEocall_Init(void);

#endif
