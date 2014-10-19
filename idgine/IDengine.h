/** \file
 * This file contains the header definitions for the object which
 * implements the generation of identities
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_IDengine_HEADER
#define NAAAIM_IDengine_HEADER


/* Object type definitions. */
typedef struct NAAAIM_IDengine * IDengine;

typedef struct NAAAIM_IDengine_State * IDengine_State;

/* Types of identities. */
typedef enum {
        IDengine_user,
	IDengine_device,
	IDengine_service
} IDengine_identity;

/**
 * External IDmgr object representation.
 */
struct NAAAIM_IDengine
{
	/* External methods. */
	_Bool (*setup)(const IDengine);
	_Bool (*attach)(const IDengine);

	_Bool (*get_id_info)(const IDengine, IDengine_identity *, \
			     const String, const String);

	_Bool (*get_identity)(const IDengine, const IDengine_identity, \
			      const String, const String, const Buffer);
	_Bool (*set_identity)(const IDengine, const Identity);

	void (*whack)(const IDengine);

	/* Private state. */
	IDengine_State state;
};


/* IDenginer constructor call. */
extern IDengine NAAAIM_IDengine_Init(void);

#endif
