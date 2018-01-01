/** \file
 * This file contains definitions for an object which implements
 * management of SGX provisiong messages.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

#ifndef NAAAIM_SGXmessage_HEADER
#define NAAAIM_SGXmessage_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXmessage * SGXmessage;

typedef struct NAAAIM_SGXmessage_State * SGXmessage_State;

/**
 * External SGXmessage object representation.
 */
struct NAAAIM_SGXmessage
{
	/* External methods. */
	void (*init_request)(const SGXmessage, uint8_t, uint8_t, uint8_t, \
			     const uint8_t *);
	_Bool (*encode_es_request)(const SGXmessage, uint8_t, uint8_t);

	_Bool (*encode)(const SGXmessage, const String);
	_Bool (*decode)(const SGXmessage, const String);

	size_t (*message_count)(const SGXmessage);
	_Bool (*get_message)(const SGXmessage, uint8_t, uint8_t, const Buffer);

	_Bool (*get_xid)(const SGXmessage, const Buffer);

	void (*dump)(const SGXmessage);
	void (*whack)(const SGXmessage);


	/* Private state. */
	SGXmessage_State state;
};


/* Sgxmetadata constructor call. */
extern SGXmessage NAAAIM_SGXmessage_Init(void);

#endif
