/** \file
 * This file contains the header definitions for the TSEMevent object
 * that implements parsing of events from the Trusted Security Event
 * Modeling system in the Linux kernel.
 */

/**************************************************************************
 * Copyright (c) 2023, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_TSEMevent_HEADER
#define NAAAIM_TSEMevent_HEADER

/* TSEM event definitions. */
enum TSEM_export_type {
	TSEM_EVENT_AGGREGATE = 0,
	TSEM_EVENT_EVENT,
	TSEM_EVENT_LOG,
	TSEM_EVENT_UNKNOWN,
};

/* Object type definitions. */
typedef struct NAAAIM_TSEMevent * TSEMevent;

typedef struct NAAAIM_TSEMevent_State * TSEMevent_State;

/**
 * External TSEMevent object representation.
 */
struct NAAAIM_TSEMevent
{
	/* External methods. */
	_Bool (*set_event)(const TSEMevent, const String);
	_Bool (*read_event)(const TSEMevent, const int fd);

	enum TSEM_export_type (*extract_export)(const TSEMevent);
	_Bool (*extract_event)(const TSEMevent);
	_Bool (*extract_field)(const TSEMevent, const char *);

	_Bool (*get_text)(const TSEMevent, const char *, const String);
	_Bool (*get_integer)(const TSEMevent, const char *, long long int *);
	_Bool (*encode_event)(const TSEMevent, const String);

	void (*reset)(const TSEMevent);
	void (*whack)(const TSEMevent);

	/* Private state. */
	TSEMevent_State state;
};


/* TSEMevent constructor call. */
extern TSEMevent NAAAIM_TSEMevent_Init(void);

#endif
