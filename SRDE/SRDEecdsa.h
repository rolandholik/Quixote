/** \file
 * This file contains definitions for an object which implements
 * ECC256 based digital signatures.  It is currently designed to be
 * a wrapper object around the Intel supplied cryptography routines
 * in order to resist namespace cross pollination.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEecdsa_HEADER
#define NAAAIM_SRDEecdsa_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEecdsa * SRDEecdsa;

typedef struct NAAAIM_SRDEecdsa_State * SRDEecdsa_State;

/**
 * External SRDEecdsa object representation.
 */
struct NAAAIM_SRDEecdsa
{
	/* External methods. */
	_Bool (*verify)(const SRDEecdsa, const Buffer, const Buffer, \
			const Buffer);

	void (*whack)(const SRDEecdsa);


	/* Private state. */
	SRDEecdsa_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SRDEecdsa NAAAIM_SRDEecdsa_Init(void);
#endif
