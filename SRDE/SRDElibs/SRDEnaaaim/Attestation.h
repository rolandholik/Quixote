/** \file
 * This file contains the API definitions for an object that is used
 * access SRDE attestation services.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_Attestation_HEADER
#define NAAAIM_Attestation_HEADER


/* Object type definitions. */
typedef struct NAAAIM_Attestation * Attestation;

typedef struct NAAAIM_Attestation_State * Attestation_State;


/**
 * External Attestation object representation.
 */
struct NAAAIM_Attestation
{
	/* External methods. */
	_Bool (*generate)(const Attestation, const Buffer, const Buffer, \
			  const String);

	void (*whack)(const Attestation);

	/* Private state. */
	Attestation_State state;
};


/* Attestation constructor call. */
extern HCLINK Attestation NAAAIM_Attestation_Init(void);
#endif
