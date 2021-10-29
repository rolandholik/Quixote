/** \file
 * This file contains the header and API definitions for an object
 * which is used to implement and manage an instance of a Turing
 * Security Event Model (TSEM).
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_TSEM_HEADER
#define NAAAIM_TSEM_HEADER


/* Object type definitions. */
typedef struct NAAAIM_TSEM * TSEM;

typedef struct NAAAIM_TSEM_State * TSEM_State;

/**
 * External ExchangeEvent object representation.
 */
struct NAAAIM_TSEM
{
	/* External methods. */
	_Bool (*update)(const TSEM, const SecurityEvent, _Bool *, \
			_Bool *, _Bool *);
	_Bool (*load)(const TSEM, const String);

	_Bool (*set_aggregate)(const TSEM, const Buffer);

	_Bool (*add_TE_event)(const TSEM, const String);
	_Bool (*get_TE_event)(const TSEM, String *);
	size_t (*TE_events_size)(const TSEM);
	void (*TE_rewind_event)(const TSEM);

	_Bool (*get_measurement)(const TSEM, const Buffer);
	_Bool (*get_state)(const TSEM, const Buffer);
	_Bool (*discipline_pid)(const TSEM, pid_t *);

	void (*rewind_event)(const TSEM);
	_Bool (*get_event)(const TSEM, SecurityEvent *);
	size_t (*trajectory_size)(const TSEM);

	void (*rewind_points)(const TSEM);
	_Bool (*get_point)(const TSEM, SecurityPoint *);
	size_t (*points_size)(const TSEM);

	void (*rewind_forensics)(const TSEM);
	_Bool (*get_forensics)(const TSEM, SecurityEvent *);
	size_t (*forensics_size)(const TSEM);

	void (*dump_events)(const TSEM);
	void (*dump_points)(const TSEM);
	void (*dump_forensics)(const TSEM);

	void (*seal)(const TSEM);
	void (*whack)(const TSEM);

	/* Private state. */
	TSEM_State state;
};


/* Exchange event constructor call. */
extern HCLINK TSEM NAAAIM_TSEM_Init(void);
#endif
