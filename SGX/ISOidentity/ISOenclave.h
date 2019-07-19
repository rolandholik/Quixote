/** \file
 * This file contains the header and API definitions for an object
 * which is used to manage communications with an ISOidentity model
 * instance running in an SGX enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_ISOenclave_HEADER
#define NAAAIM_ISOenclave_HEADER


/* Object type definitions. */
typedef struct NAAAIM_ISOenclave * ISOenclave;

typedef struct NAAAIM_ISOenclave_State * ISOenclave_State;


/**
 * Enumeration type which defines the userspace action being requested.
 */
enum ISOenclave_ocalls {
	ISOenclave_discipline,
	ISOenclave_END
};


/**
 * Structure which marshalls the data for the call into and out of
 * the the ISOenclave ocall.
 */
struct ISOenclave_ocall {
	_Bool retn;
	_Bool debug;

	enum ISOenclave_ocalls ocall;

	pid_t pid;
};


/**
 * External ExchangeEvent object representation.
 */
struct NAAAIM_ISOenclave
{
	/* External methods. */
	_Bool (*load_enclave)(const ISOenclave, const char *, const char *);

	_Bool (*update)(const ISOenclave, const String, _Bool *);
	_Bool (*update_map)(const ISOenclave, const Buffer);

	_Bool (*set_aggregate)(const ISOenclave, const Buffer);

	_Bool (*add_ai_event)(const ISOenclave, const String);

	_Bool (*get_measurement)(const ISOenclave, const Buffer);
	_Bool (*discipline_pid)(const ISOenclave, pid_t *);

	void (*rewind_event)(const ISOenclave);
	_Bool (*get_event)(const ISOenclave, String);

	void (*rewind_contours)(const ISOenclave);
	_Bool (*get_contour)(const ISOenclave, Buffer);

	void (*rewind_forensics)(const ISOenclave);
	_Bool (*get_forensics)(const ISOenclave, String);
	size_t (*forensics_size)(const ISOenclave);

	void (*dump_events)(const ISOenclave);
	void (*dump_contours)(const ISOenclave);
	void (*dump_forensics)(const ISOenclave);

	_Bool (*manager)(const ISOenclave, const Buffer, uint16_t, char *);
	_Bool (*add_verifier)(const ISOenclave, const Buffer);

	_Bool (*seal)(const ISOenclave);
	size_t (*size)(const ISOenclave);

	_Bool (*generate_identity)(const ISOenclave, const Buffer);
	void (*debug)(const ISOenclave, _Bool);
	void (*whack)(const ISOenclave);

	/* Private state. */
	ISOenclave_State state;
};


/* Exchange event constructor call. */
extern HCLINK ISOenclave NAAAIM_ISOenclave_Init(void);
#endif
