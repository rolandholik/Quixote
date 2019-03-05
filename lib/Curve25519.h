/** \file
 * This file contains the API and method descriptions for an object
 * which implements elliptic curve cryptography using Daniel
 * Bernstein's curve25519 implementation.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Curve25519_HEADER
#define NAAAIM_Curve25519_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Curve25519 * Curve25519;

typedef struct NAAAIM_Curve25519_State * Curve25519_State;

/**
 * External Curve25519 object representation.
 */
struct NAAAIM_Curve25519
{
	/* External methods. */
	_Bool (*generate)(const Curve25519);
	_Bool (*compute)(const Curve25519, const Buffer, const Buffer);
	Buffer (*get_public)(const Curve25519);

	_Bool (*poisoned)(const Curve25519);
	void (*whack)(const Curve25519);

	/* Private state. */
	Curve25519_State state;
};


/* Curve25519 constructor call. */
extern Curve25519 NAAAIM_Curve25519_Init(void);

#endif
