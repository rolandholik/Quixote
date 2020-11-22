/** \file
 * This file contains the interface definitions for an object which
 * manages a locked implementation of a POSIX shared memory egion.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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
extern HCLINK IPC NAAAIM_IPC_Init(void);
#endif
