/** \file
 * This file contains the header definitions for the LocalDuct object
 * which implements basic UNIX domain network socket communication
 * primitives.  It is designed to be the counterpart to the Duct
 * object which implements similar support for INET based sockets.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_LocalDuct_HEADER
#define NAAAIM_LocalDuct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_LocalDuct * LocalDuct;

typedef struct NAAAIM_LocalDuct_State * LocalDuct_State;

/**
 * External LocalDuct object representation.
 */
struct NAAAIM_LocalDuct
{
	/* External methods. */
	_Bool (*init_server)(const LocalDuct);
	_Bool (*init_client)(const LocalDuct);
	_Bool (*init_port)(const LocalDuct, const char *);
	_Bool (*accept_connection)(const LocalDuct);
	_Bool (*init_connection)(const LocalDuct);
	_Bool (*send_Buffer)(const LocalDuct, const Buffer);
	_Bool (*receive_Buffer)(const LocalDuct, const Buffer);

	_Bool (*get_socket)(const LocalDuct, int *);
	_Bool (*get_fd)(const LocalDuct, int *);

	_Bool (*eof)(const LocalDuct);
	void (*reset)(const LocalDuct);
	_Bool (*whack_connection)(const LocalDuct);
	void (*whack)(const LocalDuct);

	/* Private state. */
	LocalDuct_State state;
};


/* LocalDuct constructor call. */
extern HCLINK LocalDuct NAAAIM_LocalDuct_Init(void);
#endif
