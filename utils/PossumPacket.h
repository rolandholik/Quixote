/** \file
 * This file contains the state definitions and methods for the
 * object which implements the packets which make up a POSSUM
 * identification and authentication sequence.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_PossumPacket_HEADER
#define NAAAIM_PossumPacket_HEADER


/* Object type definitions. */
typedef struct NAAAIM_PossumPacket * PossumPacket;

typedef struct NAAAIM_PossumPacket_State * PossumPacket_State;

/**
 * External PossumPacket object representation.
 */
struct NAAAIM_PossumPacket
{
	/* External methods. */
	_Bool (*create_packet1)(const PossumPacket, const IDtoken);
	_Bool (*get_authenticator)(const PossumPacket, const IDtoken, \
				   const Buffer);
	_Bool (*add_element)(const PossumPacket, const Buffer);
	_Bool (*get_element)(const PossumPacket, const Buffer);
	_Bool (*encrypt)(const PossumPacket);
	_Bool (*decrypt)(const PossumPacket);
	_Bool (*encode_packet1)(const PossumPacket, const Buffer);
	_Bool (*decode_packet1)(const PossumPacket, const Buffer);
	void (*print)(const PossumPacket);
	void (*reset)(const PossumPacket);
	void (*whack)(const PossumPacket);

	/* Private state. */
	PossumPacket_State state;
};


/* PossumPacket constructor call. */
extern PossumPacket NAAAIM_PossumPacket_Init(void);
#endif
