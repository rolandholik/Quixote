/** \file
 * This file contains the header and API definitions for the object
 * that implements the modeling and dynamic evaluation of a security
 * interaction event in the Turing Security Event Model.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_EventModel_HEADER
#define NAAAIM_EventModel_HEADER


/* Object type definitions. */
typedef struct NAAAIM_EventModel * EventModel;

typedef struct NAAAIM_EventModel_State * EventModel_State;

/**
 * External EventModel object representation.
 */
struct NAAAIM_EventModel
{
	/* External methods. */
	_Bool (*add_pseudonym)(const EventModel, const Buffer);

	_Bool (*evaluate)(const EventModel, const SecurityEvent);

	void (*whack)(const EventModel);

	/* Private state. */
	EventModel_State state;
};


/* Exchange event constructor call. */
extern HCLINK EventModel NAAAIM_EventModel_Init(void);
#endif
