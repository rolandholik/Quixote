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

	SRDEpipe_whack,

	SRDEpipe_END
};


/**
 * Structure which marshalls the data for the OCALL from the enclave
 * to standard userspace that implements the desired object function.
 */
struct SRDEpipe_ocall {
	_Bool retn;

	enum SRDEpipe_ocalls ocall;
	unsigned int instance;
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
	void (*whack)(const SRDEpipe);

	/* Private state. */
	SRDEpipe_State state;
};


/* SRDEpipe constructor call. */
extern HCLINK SRDEpipe NAAAIM_SRDEpipe_Init(void);
#endif
