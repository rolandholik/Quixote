/** \file
 * This file contains the header and API definitions for an object
 * that implements parsing of a TSEM security state event description.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_EventParser_HEADER
#define NAAAIM_EventParser_HEADER


/* Object type definitions. */
typedef struct NAAAIM_EventParser * EventParser;

typedef struct NAAAIM_EventParser_State * EventParser_State;

/**
 * External EventParser object representation.
 */
struct NAAAIM_EventParser
{
	/* External methods. */
	_Bool (*extract_field)(const EventParser, const String, const char *);

	_Bool (*get_field)(const EventParser, const String);
	_Bool (*get_integer)(const EventParser, const char *, long int *);
	_Bool (*get_text)(const EventParser, const char *, const String);

	void (*print)(const EventParser);
	void (*reset)(const EventParser);
	void (*whack)(const EventParser);

	/* Private state. */
	EventParser_State state;
};


/* Exchange event constructor call. */
extern HCLINK EventParser NAAAIM_EventParser_Init(void);
#endif
