/** \file
 *
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_ESclient_HEADER
#define NAAAIM_ESclient_HEADER


/* Object type definitions. */
typedef struct NAAAIM_ESclient * ESclient;

typedef struct NAAAIM_ESclient_State * ESclient_State;

/**
 * External ESclient object representation.
 */
struct NAAAIM_ESclient
{
	/* External methods. */
	_Bool (*init)(const ESclient, const char *, const char *, \
		      const char *, const char *, const char *, const Buffer);

	_Bool (*inject)(const ESclient, const String);
	_Bool (*list)(const ESclient);
	_Bool (*scroll)(const ESclient, const String);
	_Bool (*next)(const ESclient, const String);

	void (*whack)(const ESclient);

	/* Private state. */
	ESclient_State state;
};


/* ESclient constructor call. */
extern HCLINK ESclient NAAAIM_ESclient_Init(void);

#endif
