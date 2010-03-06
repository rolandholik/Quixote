/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_OrgSearch_HEADER
#define NAAAIM_OrgSearch_HEADER

/* Include files. */
#include <stddef.h>
#include <stdbool.h>

#include <Origin.h>
#include <Buffer.h>

#include "IDtoken.h"


/* Object type definitions. */
typedef struct NAAAIM_OrgSearch * OrgSearch;

typedef struct NAAAIM_OrgSearch_State * OrgSearch_State;

/**
 * External OrgSearch object representation.
 */
struct NAAAIM_OrgSearch
{
	/* External methods. */
	unsigned int (*load)(const OrgSearch, const char *);
	_Bool (*search)(const OrgSearch, const IDtoken);
	_Bool (*get_match)(const OrgSearch, const Buffer);
	void (*whack)(const OrgSearch);

	/* Private state. */
	OrgSearch_State state;
};


/* OrgSearch constructor call. */
extern OrgSearch NAAAIM_OrgSearch_Init(void);

#endif
