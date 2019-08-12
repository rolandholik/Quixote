/** \file
 * This file defines the object state and API definitions for the
 * object which implements RSA encryption and decryption using
 * a raw RSA key which is supplied in the SGX_pek structure by
 * the Intel provisioning servers.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDErsa_HEADER
#define NAAAIM_SRDErsa_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDErsa * SRDErsa;

typedef struct NAAAIM_SRDErsa_State * SRDErsa_State;

/**
 * External SRDErsa object representation.
 */
struct NAAAIM_SRDErsa
{
	/* External methods. */
	_Bool (*init)(const SRDErsa, struct SGX_pek *);

	_Bool (*encrypt)(const SRDErsa, const Buffer, const Buffer);

	void (*dump)(const SRDErsa);
	void (*whack)(const SRDErsa);


	/* Private state. */
	SRDErsa_State state;
};


/* SRDErsa constructor call. */
extern HCLINK SRDErsa NAAAIM_SRDErsa_Init(void);
#endif
