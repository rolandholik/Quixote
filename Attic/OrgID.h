/** \file
 *
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_OrgID_HEADER
#define NAAAIM_OrgID_HEADER


/* Object type definitions. */
typedef struct NAAAIM_OrgID * OrgID;

typedef struct NAAAIM_OrgID_State * OrgID_State;

/**
 * External OrgID object representation.
 */
struct NAAAIM_OrgID
{
	/* External methods. */
	_Bool (*create)(const OrgID, const char *, const char *);
	void (*reset)(const OrgID);
	Buffer (*get_Buffer)(const OrgID);
	void (*print)(const OrgID);
	_Bool (*poisoned)(const OrgID);
	void (*whack)(const OrgID);

	/* Private state. */
	OrgID_State state;
};


/* OrgID constructor call. */
extern HCLINK OrgID NAAAIM_OrgID_Init(void);
#endif