/** \file
 * This file contains the state definitions and methods for the
 * object which manages the transmission of an EDI transaction.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_EDIpacket_HEADER
#define NAAAIM_EDIpacket_HEADER


/* Object type definitions. */
typedef struct NAAAIM_EDIpacket * EDIpacket;

typedef struct NAAAIM_EDIpacket_State * EDIpacket_State;

/* EDI packet type. */
typedef enum {
	EDIpacket_none,
	EDIpacket_decrypted,
	EDIpacket_encrypted,
	EDIpacket_getkey,
	EDIpacket_key
} EDIpacket_type;


/**
 * External EDIpacket object representation.
 */
struct NAAAIM_EDIpacket
{
	/* External methods. */
	_Bool (*set_type)(const EDIpacket, EDIpacket_type);
	EDIpacket_type (*get_type)(const EDIpacket);

	_Bool (*set_authtime)(const EDIpacket, time_t);
	time_t (*get_authtime)(const EDIpacket);

	_Bool (*set_payload)(const EDIpacket, const Buffer);
	_Bool (*get_payload)(const EDIpacket, const Buffer);

	_Bool (*encode_payload)(const EDIpacket, const Buffer);
	_Bool (*decode_payload)(const EDIpacket, const Buffer);

	void (*print)(const EDIpacket);
	void (*reset)(const EDIpacket);
	void (*whack)(const EDIpacket);

	/* Private state. */
	EDIpacket_State state;
};


/* PossumPacket constructor call. */
extern EDIpacket NAAAIM_EDIpacket_Init(void);
#endif
