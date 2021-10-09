/** \file
 * This file contains the header and API definitions for an object
 * which is used to manage and manipulate a subject identity in the
 * Turing event modeling system.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Cell_HEADER
#define NAAAIM_Cell_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Cell * Cell;

typedef struct NAAAIM_Cell_State * Cell_State;

/**
 * External Actor object representation.
 */
struct NAAAIM_Cell
{
	/* External methods. */
#if 0
	void (*set_identity_elements)(const Actor, uint32_t, uint32_t,	      \
				      uint32_t, uint32_t, uint32_t, uint32_t, \
				      uint32_t, uint32_t, uint64_t);
#endif
	_Bool (*parse)(const Cell, const String);
	_Bool (*measure)(const Cell);
	_Bool (*get_measurement)(const Cell, const Buffer);

	_Bool (*format)(const Cell, const String);

	void (*reset)(const Cell);
	void (*dump)(const Cell);
	void (*whack)(const Cell);

	/* Private state. */
	Cell_State state;
};


/* Actor constructor call. */
extern HCLINK Cell NAAAIM_Cell_Init(void);
#endif
