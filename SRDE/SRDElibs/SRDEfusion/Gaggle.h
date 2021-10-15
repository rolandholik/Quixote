/** \file
 * This file contains the API definitions for an object that manages
 * an array (gaggles) of other objects.
 */

/**************************************************************************
 * Copyright (c) 2022, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef HurdLib_Gaggle_HEADER
#define HurdLib_Gaggle_HEADER


/* Macro for adding an object to a gaggle. */
#define GADD(gaggle, ptr) gaggle->add(gaggle, (void *) &ptr)

/* Macro for converting an opaque object. */
#define GPTR(var, type) *(typeof(type) *) var

/* Macro for getting an object from a gaggle. */
#define GGET(gaggle, type) *(typeof(type) *) gaggle->get(gaggle)

/* Macro for calling the destructor on each object in a gaggle. */
#define GWHACK(gaggle, type) {			\
	typeof(type) o;				\
	size_t i = gaggle->size(gaggle);	\
	gaggle->reset(gaggle);			\
	while ( i-- ) {				\
		o = GGET(gaggle, type);		\
		o->whack(o);			\
	}					\
}


/* Object type definitions. */
typedef struct HurdLib_Gaggle * Gaggle;

typedef struct HurdLib_Gaggle_State * Gaggle_State;


/**
 * External Gaggle object representation.
 */
struct HurdLib_Gaggle
{
	/* External methods. */
	_Bool (*add)(const Gaggle, void *);
	void * (*get)(const Gaggle);

	size_t (*size)(const Gaggle);

	void (*reset)(const Gaggle);
	void (*whack)(const Gaggle);

	/* Private state. */
	Gaggle_State state;
};


/* Gaggle constructor call. */
extern Gaggle HurdLib_Gaggle_Init(void);

#endif
