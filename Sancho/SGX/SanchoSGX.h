/** \file
 * This file contains the header and API definitions for an object
 * which is used to manage communications with an ISOidentity model
 * instance running in an SGX enclave.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SanchoSGX_HEADER
#define NAAAIM_SanchoSGX_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SanchoSGX * SanchoSGX;

typedef struct NAAAIM_SanchoSGX_State * SanchoSGX_State;


/**
 * External ExchangeEvent object representation.
 */
struct NAAAIM_SanchoSGX
{
	/* External methods. */
	_Bool (*load_enclave)(const SanchoSGX, const char *, const char *);
	_Bool (*load_enclave_memory)(const SanchoSGX, const uint8_t *, \
				     size_t, const char *);

	_Bool (*update)(const SanchoSGX, const String, _Bool *);
	_Bool (*update_map)(const SanchoSGX, const Buffer);

	_Bool (*set_aggregate)(const SanchoSGX, const Buffer);

	_Bool (*add_ai_event)(const SanchoSGX, const String);
	_Bool (*get_te_event)(const SanchoSGX, const String);
	size_t (*te_size)(const SanchoSGX);
	void (*rewind_te)(const SanchoSGX);

	_Bool (*get_measurement)(const SanchoSGX, const Buffer);
	_Bool (*get_state)(const SanchoSGX, const Buffer);
	_Bool (*discipline_pid)(const SanchoSGX, pid_t *);

	void (*rewind_event)(const SanchoSGX);
	_Bool (*get_event)(const SanchoSGX, String);

	void (*rewind_points)(const SanchoSGX);
	_Bool (*get_point)(const SanchoSGX, Buffer);
	size_t (*trajectory_size)(const SanchoSGX);

	void (*rewind_forensics)(const SanchoSGX);
	_Bool (*get_forensics)(const SanchoSGX, String);
	size_t (*forensics_size)(const SanchoSGX);

	void (*dump_events)(const SanchoSGX);
	void (*dump_contours)(const SanchoSGX);
	void (*dump_forensics)(const SanchoSGX);

	_Bool (*manager)(const SanchoSGX, const Buffer, uint16_t, char *);
	_Bool (*add_verifier)(const SanchoSGX, const Buffer);

	_Bool (*seal)(const SanchoSGX);
	size_t (*size)(const SanchoSGX);

	_Bool (*generate_identity)(const SanchoSGX, const Buffer);
	void (*debug)(const SanchoSGX, _Bool);
	void (*whack)(const SanchoSGX);

	/* Private state. */
	SanchoSGX_State state;
};


/* Exchange event constructor call. */
extern HCLINK SanchoSGX NAAAIM_SanchoSGX_Init(void);
#endif
