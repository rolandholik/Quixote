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

#ifndef NAAAIM_SRDEcmac_HEADER
#define NAAAIM_SRDEcmac_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEcmac * SRDEcmac;

typedef struct NAAAIM_SRDEcmac_State * SRDEcmac_State;

/**
 * External SRDEcmac object representation.
 */
struct NAAAIM_SRDEcmac
{
	/* External methods. */
	_Bool (*compute)(const SRDEcmac, const Buffer, const Buffer, \
			 const Buffer);

	void (*whack)(const SRDEcmac);


	/* Private state. */
	SRDEcmac_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SRDEcmac NAAAIM_SRDEcmac_Init(void);
#endif
