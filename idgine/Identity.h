/** \file
 * This file contains header and definitions for the object which
 * implements the fundamental instance of an identity.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_Identity_HEADER
#define NAAAIM_Identity_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Identity * Identity;

typedef struct NAAAIM_Identity_State * Identity_State;

/**
 * External Identity object representation.
 */
struct NAAAIM_Identity
{
	/* External methods. */
	_Bool (*create)(const Identity, const OrgID, const String);

	Buffer (*get_identity)(const Identity);

	void (*reset)(const Identity);
	void (*whack)(const Identity);

	/* Private state. */
	Identity_State state;
};


/* Identity constructor call. */
extern Identity NAAAIM_Identity_Init(void);

#endif
