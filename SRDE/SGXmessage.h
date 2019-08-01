/** \file
 * This file contains definitions for an object which implements
 * management of SGX provisiong messages.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

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
	_Bool (*encode_message2)(const SGXmessage, const RandomBuffer, \
				 const PCEenclave, struct SGX_pek *,   \
				 struct SGX_report *pek_report);
	_Bool (*encode_message3)(const SGXmessage, const Buffer,      \
				 const Buffer, struct SGX_message3 *, \
				 const Buffer, const Buffer);

	_Bool (*encode)(const SGXmessage, const String);
	_Bool (*decode)(const SGXmessage, const String);

	size_t (*message_count)(const SGXmessage);
	_Bool (*get_message)(const SGXmessage, uint8_t, uint8_t, const Buffer);
	_Bool (*get_message_number)(const SGXmessage, uint8_t, uint8_t, \
				    const Buffer, uint8_t);
	_Bool (*reload_messages)(const SGXmessage, const Buffer);

	_Bool (*get_xid)(const SGXmessage, const Buffer);
	_Bool (*get_header)(const SGXmessage, const Buffer);
	_Bool (*get_response_type)(const SGXmessage, uint8_t *);

	void (*reset)(const SGXmessage);
	void (*dump)(const SGXmessage);
	void (*whack)(const SGXmessage);


	/* Private state. */
	SGXmessage_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SGXmessage NAAAIM_SGXmessage_Init(void);
#endif