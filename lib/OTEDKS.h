/** \file
 * This file contains the API definitions for an object used to create
 * symmetric keys from identity tokens using One Time Epoch
 * Differential Key Scheduling.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_OTEDKS_HEADER
#define NAAAIM_OTEDKS_HEADER


/* Object type definitions. */
typedef struct NAAAIM_OTEDKS * OTEDKS;

typedef struct NAAAIM_OTEDKS_State * OTEDKS_State;

/**
 * External OTEDKS object representation.
 */
struct NAAAIM_OTEDKS
{
	/* External methods. */

	_Bool (*create_vector1)(const OTEDKS, const Buffer);
	_Bool (*create_vector2)(const OTEDKS, const Buffer, const Buffer);
	_Bool (*iterate)(const OTEDKS);

	Buffer (*compute)(const OTEDKS, time_t, const Buffer, const Buffer);

	Buffer (*get_key)(const OTEDKS);
	Buffer (*get_iv)(const OTEDKS);

	void (*reset)(const OTEDKS);
	void (*whack)(const OTEDKS);

	/* Private state. */
	OTEDKS_State state;
};


/* OTEDKS constructor call. */
extern OTEDKS NAAAIM_OTEDKS_Init(time_t);

#endif