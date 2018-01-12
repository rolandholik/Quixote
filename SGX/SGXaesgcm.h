/** \file
 * This file contains definitions for an object which implements the
 * AES128-GCM encryption algorithm used throughout SGX for data
 * confidentiality.  It is currently designed to bea wrapper object
 * around the Intel supplied cryptography routines in order to resist
 * namespace cross pollination.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

#ifndef NAAAIM_SGXaesgcm_HEADER
#define NAAAIM_SGXaesgcm_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXaesgcm * SGXaesgcm;

typedef struct NAAAIM_SGXaesgcm_State * SGXaesgcm_State;

/**
 * External SGXaesgcm object representation.
 */
struct NAAAIM_SGXaesgcm
{
	/* External methods. */
	_Bool (*encrypt)(const SGXaesgcm, const Buffer, const Buffer, \
			 const Buffer, const Buffer, const Buffer,    \
			 const Buffer);
	_Bool (*decrypt)(const SGXaesgcm, const Buffer, const Buffer, \
			 const Buffer, const Buffer, const Buffer,    \
			 const Buffer);

	void (*whack)(const SGXaesgcm);


	/* Private state. */
	SGXaesgcm_State state;
};


/* Sgxmetadata constructor call. */
extern SGXaesgcm NAAAIM_SGXaesgcm_Init(void);
#endif
