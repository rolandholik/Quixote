/** \file
 * This file contains the API definitions for an object used to create
 * and manipulate symmetric keys to One Time Identification (OTI) 
 * identification.  This file should be included by any files which create
 * or use such objects.
 */

/**************************************************************************
 * (C)Copyright 2007, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef KerDAP_OTIkey_HEADER
#define KerDAP_OTIkey_HEADER


/* Object type definitions. */
typedef struct KerDAP_OTIkey * OTIkey;

typedef struct KerDAP_OTIkey_State * OTIkey_State;

/**
 * External OTIkey object representation.
 */
struct KerDAP_OTIkey
{
	/* External methods. */

	_Bool (*create_vector1)(const OTIkey, const Buffer);
	_Bool (*create_vector2)(const OTIkey, const Buffer, const Buffer);
	_Bool (*iterate)(const OTIkey);

	Buffer (*compute)(const OTIkey, time_t, const Buffer, const Buffer);

	Buffer (*get_key)(const OTIkey);
	Buffer (*get_iv)(const OTIkey);

	void (*reset)(const OTIkey);
	void (*whack)(const OTIkey);

	/* Private state. */
	OTIkey_State state;
};


/* OTIkey constructor call. */
extern OTIkey KerDAP_OTIkey_Init(time_t);

#endif
