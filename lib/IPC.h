/** \file
 * This file contains the interface definitions for an object which
 * manages a locked implementation of a POSIX shared memory egion.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_IPC_HEADER
#define NAAAIM_IPC_HEADER


/* Object type definitions. */
typedef struct NAAAIM_IPC * IPC;

typedef struct NAAAIM_IPC_State * IPC_State;

/**
 * External IPC object representation.
 */
struct NAAAIM_IPC
{
	/* External methods. */
	_Bool (*create)(const IPC, const char *, off_t);
	_Bool (*attach)(const IPC, const char *);

	_Bool (*copy)(const IPC, const unsigned char *, off_t, off_t);
	void * (*get)(const IPC);

	_Bool (*lock)(const IPC);
	_Bool (*unlock)(const IPC);

	void (*whack)(const IPC);

	/* Private state. */
	IPC_State state;
};


/* IPC constructor call. */
extern IPC NAAAIM_IPC_Init(void);

#endif
