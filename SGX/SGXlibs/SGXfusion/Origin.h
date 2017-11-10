/** \file
 * This file should be included by any application which wants to create
 * objects managed within a HurdLib programming object tree.
 */

/**************************************************************************
 * (C)Copyright 2006, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef HurdLib_Origin_HEADER
#define HurdLib_Origin_HEADER


/* Object type definitions. */
typedef struct HurdLib_Origin * Origin;

typedef struct HurdLib_Origin_State * Origin_State;

/**
 * The following struct is used to pass and return object information to
 * and from the generic object constructor.
 */
struct HurdLib_Origin_Retn
{
	/* External object representation. */
	size_t object_size;
	void *object;

	/* Internal object state information. */
	size_t state_size;
	void *state;
};


/**
 * External Origin object representation.
 */
struct HurdLib_Origin
{
	/* External methods. */
	_Bool (*init)(const Origin, int, int, struct HurdLib_Origin_Retn *);
	void (*whack)(const Origin, void *, void *);
	void (*iprint)(const Origin, int, char const *, ...);

	/* Private state. */
	Origin_State state;
};


/* Origin constructor call. */
extern Origin HurdLib_Origin_Init(void);

#endif
