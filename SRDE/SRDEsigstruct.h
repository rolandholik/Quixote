/** \file
 * This file contains interface definitions for an object which is used to
 * manipulate an Software Guard Extensions (SGX) signature structure.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEsigstruct_HEADER
#define NAAAIM_SRDEsigstruct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEsigstruct * SRDEsigstruct;

typedef struct NAAAIM_SRDEsigstruct_State * SRDEsigstruct_State;

/**
 * External SGXMetadata object representation.
 */
struct NAAAIM_SRDEsigstruct
{
	/* External methods. */
	_Bool (*load)(const SRDEsigstruct, const char *);

	_Bool (*get)(const SRDEsigstruct, struct SGX_sigstruct *);
	_Bool (*get_LE)(const SRDEsigstruct, struct SGX_sigstruct *);

	_Bool (*generate)(const SRDEsigstruct);
	void (*dump)(const SRDEsigstruct);
	void (*whack)(const SRDEsigstruct);

	/* Private state. */
	SRDEsigstruct_State state;
};


/* SGXMetadata constructor call. */
extern HCLINK SRDEsigstruct NAAAIM_SRDEsigstruct_Init(void);
#endif
