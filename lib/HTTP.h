/** \file
 * This file contains the definitions for an object which implements
 * the execution of HTTP requests.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_HTTP_HEADER
#define NAAAIM_HTTP_HEADER


/* Object type definitions. */
typedef struct NAAAIM_HTTP * HTTP;

typedef struct NAAAIM_HTTP_State * HTTP_State;


/**
 * External HTTP object representation.
 */
struct NAAAIM_HTTP
{
	_Bool (*add_arg)(const HTTP, const char *);

	_Bool (*post)(const HTTP, const char *, const Buffer, const Buffer);

	void (*whack)(const HTTP);

	/* Private state. */
	HTTP_State state;
};


/* HTTP constructor call. */
extern HTTP NAAAIM_HTTP_Init(void);

#endif