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

#ifndef NAAAIM_SGXsigstruct_HEADER
#define NAAAIM_SGXsigstruct_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXsigstruct * SGXsigstruct;

typedef struct NAAAIM_SGXsigstruct_State * SGXsigstruct_State;

/**
 * External SGXMetadata object representation.
 */
struct NAAAIM_SGXsigstruct
{
	/* External methods. */
	_Bool (*load)(const SGXsigstruct, const char *);

	_Bool (*get)(const SGXsigstruct, struct SGX_sigstruct *);
	_Bool (*get_LE)(const SGXsigstruct, struct SGX_sigstruct *);

	_Bool (*generate)(const SGXsigstruct);
	void (*dump)(const SGXsigstruct);
	void (*whack)(const SGXsigstruct);

	/* Private state. */
	SGXsigstruct_State state;
};


/* SGXMetadata constructor call. */
extern SGXsigstruct NAAAIM_SGXsigstruct_Init(void);

#endif
