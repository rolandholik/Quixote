/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2009, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_IDsignature_HEADER
#define NAAAIM_IDsignature_HEADER


/* Object type definitions. */
typedef struct NAAAIM_IDsignature * IDsignature;

typedef struct NAAAIM_IDsignature_State * IDsignature_State;

/**
 * External IDsignature object representation.
 */
struct NAAAIM_IDsignature
{
	/* External methods. */
	void (*whack)(const IDsignature);

	/* Private state. */
	IDsignature_State state;
};


/* IDsignature constructor call. */
extern IDsignature NAAAIM_IDsignature_Init(void);

#endif
