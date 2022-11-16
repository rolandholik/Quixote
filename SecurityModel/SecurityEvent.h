/** \file
 * This file contains the header and API definitions for an object
 * which is used to manage and manipulate an information exchange
 * event in the iso-identity behavior modeling architecture.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SecurityEvent_HEADER
#define NAAAIM_SecurityEvent_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SecurityEvent * SecurityEvent;

typedef struct NAAAIM_SecurityEvent_State * SecurityEvent_State;

/**
 * External SecurityEvent object representation.
 */
struct NAAAIM_SecurityEvent
{
	/* External methods. */
	_Bool (*parse)(const SecurityEvent, const String);
	_Bool (*measure)(const SecurityEvent);
	_Bool (*evaluate_pseudonym)(const SecurityEvent, const Buffer);

	_Bool (*get_identity)(const SecurityEvent, const Buffer);
	_Bool (*get_event)(const SecurityEvent, const String);
	_Bool (*get_pid)(const SecurityEvent, pid_t *);

	_Bool (*format)(const SecurityEvent, const String);
	_Bool (*format_generic)(const SecurityEvent, const String);

	void (*reset)(const SecurityEvent);
	void (*dump)(const SecurityEvent);
	void (*whack)(const SecurityEvent);

	/* Private state. */
	SecurityEvent_State state;
};


/* Exchange event constructor call. */
extern HCLINK SecurityEvent NAAAIM_SecurityEvent_Init(void);
#endif
