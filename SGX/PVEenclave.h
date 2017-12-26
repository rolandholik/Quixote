/** \file
 * This file contains definitions for an object which implements
 * management of provisioning enclaves.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

#ifndef NAAAIM_PVEenclave_HEADER
#define NAAAIM_PVEenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_PVEenclave * PVEenclave;

typedef struct NAAAIM_PVEenclave_State * PVEenclave_State;

/**
 * External PVEenclave object representation.
 */
struct NAAAIM_PVEenclave
{
	/* External methods. */
	_Bool (*open)(const PVEenclave, const char *);

	_Bool (*get_endpoint)(const PVEenclave);
	_Bool (*generate_message1)(const PVEenclave, const SGXmessage);

	void (*whack)(const PVEenclave);


	/* Private state. */
	PVEenclave_State state;
};


/* Sgxmetadata constructor call. */
extern PVEenclave NAAAIM_PVEenclave_Init(void);

#endif
