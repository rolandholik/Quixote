/** \file
 * This file contains definitions for an object which implements
 * management of an provisioned EPID blob.
 */

/*
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */

#ifndef NAAAIM_SGXepid_HEADER
#define NAAAIM_SGXepid_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXepid * SGXepid;

typedef struct NAAAIM_SGXepid_State * SGXepid_State;

/**
 * External SGXepid object representation.
 */
struct NAAAIM_SGXepid
{
	/* External methods. */
	_Bool (*load)(const SGXepid, const char *);
	_Bool (*save)(const SGXepid, const char *);

	_Bool (*add_epid)(const SGXepid, const Buffer);
        void (*add_platform_info)(const SGXepid, struct SGX_platform_info *);

	Buffer (*get_epid)(const SGXepid);

	void (*dump)(const SGXepid);
	void (*whack)(const SGXepid);


	/* Private state. */
	SGXepid_State state;
};


/* Sgxmetadata constructor call. */
extern SGXepid NAAAIM_SGXepid_Init(void);

#endif
