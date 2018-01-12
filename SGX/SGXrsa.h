/** \file
 * This file defines the object state and API definitions for the
 * object which implements RSA encryption and decryption using
 * a raw RSA key which is supplied in the SGX_pek structure by
 * the Intel provisioning servers.
 */

/*
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

#ifndef NAAAIM_SGXrsa_HEADER
#define NAAAIM_SGXrsa_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXrsa * SGXrsa;

typedef struct NAAAIM_SGXrsa_State * SGXrsa_State;

/**
 * External SGXrsa object representation.
 */
struct NAAAIM_SGXrsa
{
	/* External methods. */
	_Bool (*init)(const SGXrsa, struct SGX_pek *);

	_Bool (*encrypt)(const SGXrsa, const Buffer, const Buffer);

	void (*dump)(const SGXrsa);
	void (*whack)(const SGXrsa);


	/* Private state. */
	SGXrsa_State state;
};


/* Sgxmetadata constructor call. */
extern SGXrsa NAAAIM_SGXrsa_Init(void);
#endif
