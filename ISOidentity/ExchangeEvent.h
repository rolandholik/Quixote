/** \file
 * This file contains the header and API definitions for an object
 * which is used to manage and manipulate an information exchange
 * event in the iso-identity behavior modeling architecture.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_ExchangeEvent_HEADER
#define NAAAIM_ExchangeEvent_HEADER


/* Object type definitions. */
typedef struct NAAAIM_ExchangeEvent * ExchangeEvent;

typedef struct NAAAIM_ExchangeEvent_State * ExchangeEvent_State;

/**
 * External ExchangeEvent object representation.
 */
struct NAAAIM_ExchangeEvent
{
	/* External methods. */
	_Bool (*parse)(const ExchangeEvent, const String);
	_Bool (*measure)(const ExchangeEvent);

	_Bool (*get_identity)(const ExchangeEvent, const Buffer);
	_Bool (*get_event)(const ExchangeEvent, const String);
	_Bool (*get_pid)(const ExchangeEvent, pid_t *);

	_Bool (*format)(const ExchangeEvent, const String);

	void (*reset)(const ExchangeEvent);
	void (*dump)(const ExchangeEvent);
	void (*whack)(const ExchangeEvent);

	/* Private state. */
	ExchangeEvent_State state;
};


/* Exchange event constructor call. */
extern ExchangeEvent NAAAIM_ExchangeEvent_Init(void);
#endif
