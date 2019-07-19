/** \file
 * This file contains definitions for an object which implements
 * the AES128-CMAC algorithm used for SGX signatures.  It is currently
 * designed to bea wrapper object around the Intel supplied cryptography
 * routines in order to resist namespace cross pollination.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SGXcmac_HEADER
#define NAAAIM_SGXcmac_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXcmac * SGXcmac;

typedef struct NAAAIM_SGXcmac_State * SGXcmac_State;

/**
 * External SGXcmac object representation.
 */
struct NAAAIM_SGXcmac
{
	/* External methods. */
	_Bool (*compute)(const SGXcmac, const Buffer, const Buffer, \
			 const Buffer);

	void (*whack)(const SGXcmac);


	/* Private state. */
	SGXcmac_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SGXcmac NAAAIM_SGXcmac_Init(void);
#endif
