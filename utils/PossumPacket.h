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

/* Definitions for IPsec parameters types. */
#define POSSUM_PACKET_TRIPLEDES_CBC	1
#define POSSUM_PACKET_AES128_CBC	2

#define POSSUM_PACKET_HMAC_MD5		1
#define POSSUM_PACKET_HMAC_SHA1		2

#define POSSUM_PACKET_EC		1
#define POSSUM_PACKET_CURVE25519	1


/* Object type definitions. */
typedef struct NAAAIM_PossumPacket * PossumPacket;

typedef struct NAAAIM_PossumPacket_State * PossumPacket_State;

typedef enum {
	PossumPacket_replay_nonce,
	PossumPacket_quote_nonce,
	PossumPacket_public,
	PossumPacket_hardware
} PossumPacket_element;

typedef enum {
	PossumPacket_spi,
	PossumPacket_protocol
} PossumPacket_value;

/**
 * External PossumPacket object representation.
 */
struct NAAAIM_PossumPacket
{
	/* External methods. */
	_Bool (*create_packet1)(const PossumPacket, const IDtoken, \
				const Curve25519, const uint32_t);
	_Bool (*encode_packet1)(const PossumPacket, const Buffer, \
				const Buffer);
	_Bool (*decode_packet1)(const PossumPacket, const IDtoken, \
				const Buffer, const Buffer);
	_Bool (*set_schedule)(const PossumPacket, const IDtoken, \
			      time_t);
	uint32_t (*get_value)(const PossumPacket, const PossumPacket_value);
	Buffer (*get_element)(const PossumPacket, const PossumPacket_element);
	void (*print)(const PossumPacket);
	void (*reset)(const PossumPacket);
	void (*whack)(const PossumPacket);

	/* Private state. */
	PossumPacket_State state;
};


/* PossumPacket constructor call. */
extern PossumPacket NAAAIM_PossumPacket_Init(void);
#endif
