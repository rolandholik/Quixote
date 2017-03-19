/** \file
 * This file contains the header and API definitions for an object
 * which is used to manage and manipulate an actor identity in the
 * iso-identity kernel modeling system.
 */

/**************************************************************************
 * (C)Copyright 2017, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_Actor_HEADER
#define NAAAIM_Actor_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Actor * Actor;

typedef struct NAAAIM_Actor_State * Actor_State;

/**
 * External Actor object representation.
 */
struct NAAAIM_Actor
{
	/* External methods. */
	void (*set_identity_elements)(const Actor, uint32_t, uint32_t,	      \
				      uint32_t, uint32_t, uint32_t, uint32_t, \
				      uint32_t, uint32_t, uint64_t);
	_Bool (*parse)(const Actor, const String);
	_Bool (*measure)(const Actor);
	_Bool (*get_measurement)(const Actor, const Buffer);

	void (*reset)(const Actor);
	void (*dump)(const Actor);
	void (*whack)(const Actor);

	/* Private state. */
	Actor_State state;
};


/* Actor constructor call. */
extern Actor NAAAIM_Actor_Init(void);

#endif
