/** \file
 * This file contains the header and API definitions for an object
 * that is used to manage the parameters associated with a context
 * of execution in a Turing Security Event Model.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_COE_HEADER
#define NAAAIM_COE_HEADER


/* Object type definitions. */
typedef struct NAAAIM_COE * COE;

typedef struct NAAAIM_COE_State * COE_State;

/**
 * External COE object representation.
 */
struct NAAAIM_COE
{
	/* External methods. */
	void (*set_characteristics)(const COE, uint32_t, uint32_t, uint32_t, \
				    uint32_t, uint32_t, uint32_t, uint32_t,  \
				    uint32_t, uint64_t);
	_Bool (*parse)(const COE, const String);
	_Bool (*measure)(const COE);
	_Bool (*get_measurement)(const COE, const Buffer);

	_Bool (*format)(const COE, const String);

	void (*reset)(const COE);
	void (*dump)(const COE);
	void (*whack)(const COE);

	/* Private state. */
	COE_State state;
};


/* COE constructor call. */
extern HCLINK COE NAAAIM_COE_Init(void);
#endif
