/** \file
 * This file contains the API and method descriptions for an object
 * which implements elliptic curve cryptography using Daniel
 * Bernstein's curve25519 implementation.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
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
	void (*curve25519)(const Curve25519, uint8_t *, const uint8_t *, \
			   const uint8_t *);
	void (*whack)(const Curve25519);

	/* Private state. */
	Curve25519_State state;
};


/* Curve25519 constructor call. */
extern Curve25519 NAAAIM_Curve25519_Init(void);

#endif
