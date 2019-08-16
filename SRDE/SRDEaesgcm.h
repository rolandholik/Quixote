/** \file
 * This file contains definitions for an object which implements the
 * AES128-GCM encryption algorithm used throughout SGX for data
 * confidentiality.  It is currently designed to bea wrapper object
 * around the Intel supplied cryptography routines in order to resist
 * namespace cross pollination.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEaesgcm_HEADER
#define NAAAIM_SRDEaesgcm_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEaesgcm * SRDEaesgcm;

typedef struct NAAAIM_SRDEaesgcm_State * SRDEaesgcm_State;

/**
 * External SRDEaesgcm object representation.
 */
struct NAAAIM_SRDEaesgcm
{
	/* External methods. */
	_Bool (*encrypt)(const SRDEaesgcm, const Buffer, const Buffer, \
			 const Buffer, const Buffer, const Buffer,     \
			 const Buffer);
	_Bool (*decrypt)(const SRDEaesgcm, const Buffer, const Buffer, \
			 const Buffer, const Buffer, const Buffer,     \
			 const Buffer);

	void (*whack)(const SRDEaesgcm);


	/* Private state. */
	SRDEaesgcm_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SRDEaesgcm NAAAIM_SRDEaesgcm_Init(void);
#endif
