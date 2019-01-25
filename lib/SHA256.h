/** \file
 * This file contains the API definitions for an object which implements
 * cryptographic hashing via the SHA256 algorithm.  It should be included
 * by any file which creates or uses such an object.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_SHA256_HEADER
#define NAAAIM_SHA256_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SHA256 * Sha256;

typedef struct NAAAIM_SHA256_State * SHA256_State;

/**
 * External SHA256 object representation.
 */
struct NAAAIM_SHA256
{
	/* External methods. */
	_Bool (*add)(const Sha256, const Buffer);
	_Bool (*compute)(const Sha256);
	_Bool (*rehash)(const Sha256, unsigned int);
	_Bool (*extend)(const Sha256, const Buffer);
	void (*reset)(const Sha256);
	unsigned char * (*get)(const Sha256);
	Buffer (*get_Buffer)(const Sha256);
	void (*print)(const Sha256);
	void (*whack)(const Sha256);

	/* Private state. */
	SHA256_State state;
};


/* SHA256 constructor call. */
extern Sha256 NAAAIM_Sha256_Init(void);

#endif
