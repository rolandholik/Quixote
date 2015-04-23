/** \file
 * This file implements the header definitions for the object which
 * implements management of CCID smartcards.
 */

/**************************************************************************
 * (C)Copyright 2011,2015 The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
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
	_Bool (*wait_for_insertion)(const SmartCard);

	void (*whack)(const SmartCard);

	/* Private state. */
	SmartCard_State state;
};


/* SmartCard constructor call. */
extern SmartCard NAAAIM_SmartCard_Init(void);

#endif
