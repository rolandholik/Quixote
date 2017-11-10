/** \file
 * This file defines the external API for the Fibonacci sequence object.
 * It should be included by any file which desires to allocate a
 * Fibonacci sequence object.
 */

/**************************************************************************
 * (C)Copyright 2006, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef HurdLib_Fibsequence_HEADER
#define HurdLib_Fibsequence_HEADER


/* Object type definitions. */
typedef struct HurdLib_Fibsequence * Fibsequence;

typedef struct HurdLib_Fibsequence_State * Fibsequence_State;

/**
 * External Fibsequence object representation.
 */
struct HurdLib_Fibsequence
{
	/* External methods. */
	unsigned int	(*get)(const Fibsequence);
	unsigned int	(*next)(const Fibsequence);
	unsigned int	(*getAbove)(const Fibsequence, unsigned int);
	void		(*reset)(const Fibsequence);
	void		(*print)(const Fibsequence);
	void		(*dump)(const Fibsequence, int);
	void		(*whack)(const Fibsequence);

	/* Private state. */
	Fibsequence_State state;
};


/* Fibsequence constructor call. */
extern Fibsequence HurdLib_Fibsequence_Init(void);

#endif
