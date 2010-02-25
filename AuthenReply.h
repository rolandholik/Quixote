/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_AuthenReply_HEADER
#define NAAAIM_AuthenReply_HEADER

/* Include files. */
#include <stddef.h>
#include <stdbool.h>

#include <Origin.h>
#include <Buffer.h>


/* Object type definitions. */
typedef struct NAAAIM_AuthenReply * AuthenReply;

typedef struct NAAAIM_AuthenReply_State * AuthenReply_State;

/**
 * External AuthenReply object representation.
 */
struct NAAAIM_AuthenReply
{
	/* External methods. */
	_Bool (*add_elements)(const AuthenReply, const Buffer);
	_Bool (*get_elements)(const AuthenReply, const Buffer);
	_Bool (*encode)(const AuthenReply, const Buffer);
	_Bool (*decode)(const AuthenReply, const Buffer);
	void (*print)(const AuthenReply);
	void (*whack)(const AuthenReply);

	/* Private state. */
	AuthenReply_State state;
};


/* AuthenReply constructor call. */
extern AuthenReply NAAAIM_AuthenReply_Init(void);

#endif
