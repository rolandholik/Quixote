/** \file
 * This object implements the API definitions for an object used to
 * coordinate local enclave<->enclave communications.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEpipe_HEADER
#define NAAAIM_SRDEpipe_HEADER


/**
 * Enumeration type which defines the method type whose userspace
 * implementation is being requested.
 */
enum SRDEpipe_ocalls {
	SRDEpipe_init_object,

	SRDEpipe_setup,
	SRDEpipe_connect,
	SRDEpipe_send_packet,
	SRDEpipe_whack,

	SRDEpipe_END
};


/**
 * Enumerated definitions for SRDEpipe packet types.
 */
typedef enum {
	SRDEpipe_failure,
	SRDEpipe_data,
	SRDEpipe_eop
} SRDEpipe_type;


/**
 * Structure which marshalls the data for the OCALL from the enclave
 * to standard userspace that implements the desired object function.
 */
struct SRDEpipe_ocall {
	_Bool retn;

	enum SRDEpipe_ocalls ocall;
	unsigned int instance;

	_Bool debug;
	int slot;
	char enclave[128];
	char token[128];

	struct SGX_targetinfo target;
	struct SGX_report report;

	size_t bufr_size;
	uint8_t *bufr;

	uint8_t arena[];
};


/**
 * Structure which marshalls the data for the ECALL into the target
 * enclave.
 */
struct SRDEpipe_ecall {
	_Bool retn;

	struct SGX_targetinfo target;
	struct SGX_report report;

	size_t needed;
	size_t bufr_size;
	uint8_t *bufr;
};


/* Object type definitions. */
typedef struct NAAAIM_SRDEpipe * SRDEpipe;

typedef struct NAAAIM_SRDEpipe_State * SRDEpipe_State;

/**
 * External SRDEpipe object representation.
 */
struct NAAAIM_SRDEpipe
{
	/* External methods. */
	_Bool (*setup)(const SRDEpipe, const char *, const int slot, \
		       const char *, const _Bool);
	_Bool (*bind)(const SRDEpipe, struct SGX_targetinfo *, \
		   struct SGX_report *);

	_Bool (*connect)(const SRDEpipe);
	_Bool (*accept)(const SRDEpipe, struct SGX_targetinfo *, \
			struct SGX_report *);
	_Bool (*verify)(const SRDEpipe, const Buffer, _Bool *);

	_Bool (*send_packet)(const SRDEpipe, const SRDEpipe_type type, \
			     const Buffer);
	SRDEpipe_type (*receive_packet)(const SRDEpipe, const Buffer);

	_Bool (*close)(const SRDEpipe);
	_Bool (*connected)(const SRDEpipe);
	void (*whack)(const SRDEpipe);

	/* Private state. */
	SRDEpipe_State state;
};


/* SRDEpipe constructor call. */
extern HCLINK SRDEpipe NAAAIM_SRDEpipe_Init(void);
#endif
