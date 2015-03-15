/** \file
 * This file contains header definitions for the PossumPipe object
 * which implements secured communications based on the identity
 * and mutual attestation state of two devices.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_PossumPipe_HEADER
#define NAAAIM_PossumPipe_HEADER


/* Object type definitions. */
typedef struct NAAAIM_PossumPipe * PossumPipe;

typedef struct NAAAIM_PossumPipe_State * PossumPipe_State;

/**
 * External PossumPipe object representation.
 */
struct NAAAIM_PossumPipe
{
	/* External methods. */
	_Bool (*init_server)(const PossumPipe, const char *, int port, _Bool);
	_Bool (*init_client)(const PossumPipe, const char *, int port);

	_Bool (*accept_connection)(const PossumPipe);

	_Bool (*start_host_mode)(const PossumPipe);
	_Bool (*start_client_mode)(const PossumPipe);

	void (*whack)(const PossumPipe);

	/* Private state. */
	PossumPipe_State state;
};


/* PossumPipe constructor call. */
extern PossumPipe NAAAIM_PossumPipe_Init(void);

#endif
