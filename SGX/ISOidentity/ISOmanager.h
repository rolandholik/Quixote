/** \file
 * This file contains the header and API definitions for an object
 * which is used to implement the client portion of communications
 * with an ISOidentity enclave.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_ISOmanager_HEADER
#define NAAAIM_ISOmanager_HEADER


/* Object type definitions. */
typedef struct NAAAIM_ISOmanager * ISOmanager;

typedef struct NAAAIM_ISOmanager_State * ISOmanager_State;


/**
 * External ISOmanager object representation.
 */
struct NAAAIM_ISOmanager
{
	/* External methods. */
	_Bool (*load_enclave)(const ISOmanager, const char *, const char *, \
			      _Bool);
	_Bool (*connect)(const ISOmanager, char *, const unsigned int, \
			 char *, const Buffer);
	_Bool (*generate_identity)(const ISOmanager, const Buffer);
	_Bool (*add_verifier)(const ISOmanager, const Buffer);
	
	void (*debug)(const ISOmanager, _Bool);
	void (*whack)(const ISOmanager);

	/* Private state. */
	ISOmanager_State state;
};


/* Exchange event constructor call. */
extern ISOmanager NAAAIM_ISOmanager_Init(void);
#endif
