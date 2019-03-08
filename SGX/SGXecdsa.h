/** \file
 * This file contains definitions for an object which implements
 * ECC256 based digital signatures.  It is currently designed to be
 * a wrapper object around the Intel supplied cryptography routines
 * in order to resist namespace cross pollination.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SGXecdsa_HEADER
#define NAAAIM_SGXecdsa_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXecdsa * SGXecdsa;

typedef struct NAAAIM_SGXecdsa_State * SGXecdsa_State;

/**
 * External SGXecdsa object representation.
 */
struct NAAAIM_SGXecdsa
{
	/* External methods. */
	_Bool (*verify)(const SGXecdsa, const Buffer, const Buffer, \
			const Buffer);

	void (*whack)(const SGXecdsa);


	/* Private state. */
	SGXecdsa_State state;
};


/* Sgxmetadata constructor call. */
extern SGXecdsa NAAAIM_SGXecdsa_Init(void);
#endif
