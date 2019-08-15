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

#ifndef NAAAIM_SRDEmessage_HEADER
#define NAAAIM_SRDEmessage_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEmessage * SRDEmessage;

typedef struct NAAAIM_SRDEmessage_State * SRDEmessage_State;

/**
 * External SRDEmessage object representation.
 */
struct NAAAIM_SRDEmessage
{
	/* External methods. */
	void (*init_request)(const SRDEmessage, uint8_t, uint8_t, uint8_t, \
			     const uint8_t *);
	_Bool (*encode_es_request)(const SRDEmessage, uint8_t, uint8_t);
	_Bool (*encode_message2)(const SRDEmessage, const RandomBuffer, \
				 const PCEenclave, struct SGX_pek *,	\
				 struct SGX_report *pek_report);
	_Bool (*encode_message3)(const SRDEmessage, const Buffer,	\
				 const Buffer, struct SGX_message3 *,	\
				 const Buffer, const Buffer);

	_Bool (*encode)(const SRDEmessage, const String);
	_Bool (*decode)(const SRDEmessage, const String);

	size_t (*message_count)(const SRDEmessage);
	_Bool (*get_message)(const SRDEmessage, uint8_t, uint8_t, \
			     const Buffer);
	_Bool (*get_message_number)(const SRDEmessage, uint8_t, uint8_t, \
				    const Buffer, uint8_t);
	_Bool (*reload_messages)(const SRDEmessage, const Buffer);

	_Bool (*get_xid)(const SRDEmessage, const Buffer);
	_Bool (*get_header)(const SRDEmessage, const Buffer);
	_Bool (*get_response_type)(const SRDEmessage, uint8_t *);

	void (*reset)(const SRDEmessage);
	void (*dump)(const SRDEmessage);
	void (*whack)(const SRDEmessage);


	/* Private state. */
	SRDEmessage_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SRDEmessage NAAAIM_SRDEmessage_Init(void);
#endif
