/** \file
 * This file contains definitions for an object which implements
 * management of an provisioned EPID blob.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEepid_HEADER
#define NAAAIM_SRDEepid_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEepid * SRDEepid;

typedef struct NAAAIM_SRDEepid_State * SRDEepid_State;

/**
 * External SRDEepid object representation.
 */
struct NAAAIM_SRDEepid
{
	/* External methods. */
	_Bool (*load)(const SRDEepid, const char *);
	_Bool (*save)(const SRDEepid, const char *);

	_Bool (*add_epid)(const SRDEepid, const Buffer);
        void (*add_platform_info)(const SRDEepid, struct SGX_platform_info *);

	Buffer (*get_epid)(const SRDEepid);

	void (*dump)(const SRDEepid);
	void (*whack)(const SRDEepid);


	/* Private state. */
	SRDEepid_State state;
};


/* Sgxmetadata constructor call. */
extern HCLINK SRDEepid NAAAIM_SRDEepid_Init(void);
#endif
