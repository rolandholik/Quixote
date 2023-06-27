/** \file
 * This file contains the header and API definitions for an object
 * which is used to implement and manage a security state point in
 * a Turing Security Event Model.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SecurityPoint_HEADER
#define NAAAIM_SecurityPoint_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SecurityPoint * SecurityPoint;

typedef struct NAAAIM_SecurityPoint_State * SecurityPoint_State;

/**
 * External ExchangeEvent object representation.
 */
struct NAAAIM_SecurityPoint
{
	/* External methods. */
	void (*add)(const SecurityPoint, const Buffer);
	unsigned char * (*get)(const SecurityPoint);
	_Bool (*get_Buffer)(const SecurityPoint, const Buffer);

	void (*increment)(const SecurityPoint);
	uint64_t (*get_count)(const SecurityPoint);
	void (*set_count)(const SecurityPoint, uint64_t);

	void (*set_invalid)(const SecurityPoint);
	_Bool (*is_valid)(const SecurityPoint);

	_Bool (*equal)(const SecurityPoint, const SecurityPoint);

	void (*reset)(const SecurityPoint);
	void (*whack)(const SecurityPoint);

	/* Private state. */
	SecurityPoint_State state;
};


/* Exchange event constructor call. */
extern HCLINK SecurityPoint NAAAIM_SecurityPoint_Init(void);
#endif
