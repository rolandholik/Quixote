/** \file
 *
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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
	_Bool (*setup_parallel)(const OrgSearch, unsigned int);
	_Bool (*get_match)(const OrgSearch, const Buffer);
	void (*whack)(const OrgSearch);

	/* Private state. */
	OrgSearch_State state;
};


/* OrgSearch constructor call. */
extern HCLINK OrgSearch NAAAIM_OrgSearch_Init(void);
#endif
