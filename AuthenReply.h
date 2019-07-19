/** \file
 *
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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
extern HCLINK AuthenReply NAAAIM_AuthenReply_Init(void);
#endif
