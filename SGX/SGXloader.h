/** \file
 * This file contains definitions for an object which implements the
 * loading of the binary contents of a Software Guard Extensions (SGX)
 * enclave.
 */

/**************************************************************************
 * (C)Copyright 2016, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_SGXloader_HEADER
#define NAAAIM_SGXloader_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXloader * SGXloader;

typedef struct NAAAIM_SGXloader_State * SGXloader_State;

/**
 * External SGXloader object representation.
 */
struct NAAAIM_SGXloader
{
	/* External methods. */
	_Bool (*load)(const SGXloader, const char *, _Bool);
	_Bool (*load_secs)(const SGXloader, const char *, struct SGX_secs *, \
			   _Bool);

	_Bool (*load_segments)(const SGXloader, const SGXenclave);
	_Bool (*load_layouts)(const SGXloader, const SGXenclave);

	_Bool (*get_sigstruct)(const SGXloader, struct SGX_sigstruct *);
	_Bool (*get_attributes)(const SGXloader, sgx_attributes_t *);

	void (*debug)(const SGXloader, const _Bool);
	void (*dump)(const SGXloader);
	void (*whack)(const SGXloader);

	/* Private state. */
	SGXloader_State state;
};


/* SGXMetadata constructor call. */
extern SGXloader NAAAIM_SGXloader_Init(void);

#endif
