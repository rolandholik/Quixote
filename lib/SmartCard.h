/** \file
 * This file implements the header definitions for the object which
 * implements management of CCID smartcards.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SmartCard_HEADER
#define NAAAIM_SmartCard_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SmartCard * SmartCard;

typedef struct NAAAIM_SmartCard_State * SmartCard_State;

/**
 * External SmartCard object representation.
 */
struct NAAAIM_SmartCard
{
	/* External methods. */
	_Bool (*get_readers)(const SmartCard, int *);
	_Bool (*wait_for_reader)(const SmartCard, int *);

	_Bool (*wait_for_insertion)(const SmartCard);

	void (*whack)(const SmartCard);

	/* Private state. */
	SmartCard_State state;
};


/* SmartCard constructor call. */
extern HCLINK SmartCard NAAAIM_SmartCard_Init(void);
#endif
