/** \file
 * This file contains the header and API definitions for an object
 * which is used to implement and manage  single instance of an iso-identity
 * behavioral model.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_ISOidentity_HEADER
#define NAAAIM_ISOidentity_HEADER


/* Object type definitions. */
typedef struct NAAAIM_ISOidentity * ISOidentity;

typedef struct NAAAIM_ISOidentity_State * ISOidentity_State;

/**
 * External ExchangeEvent object representation.
 */
struct NAAAIM_ISOidentity
{
	/* External methods. */
	_Bool (*update)(const ISOidentity, const ExchangeEvent, _Bool *);

	_Bool (*set_aggregate)(const ISOidentity, const Buffer);

	_Bool (*get_measurement)(const ISOidentity, const Buffer);

	void (*rewind_event)(const ISOidentity);
	_Bool (*get_event)(const ISOidentity, ExchangeEvent *);

	void (*dump_events)(const ISOidentity);
	void (*dump_contours)(const ISOidentity);
	void (*whack)(const ISOidentity);

	/* Private state. */
	ISOidentity_State state;
};


/* Exchange event constructor call. */
extern ISOidentity NAAAIM_ISOidentity_Init(void);
#endif
