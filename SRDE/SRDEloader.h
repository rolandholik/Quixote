/** \file
 * This file contains definitions for an object which implements the
 * loading of the binary contents of a Software Guard Extensions (SGX)
 * enclave.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEloader_HEADER
#define NAAAIM_SRDEloader_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEloader * SRDEloader;

typedef struct NAAAIM_SRDEloader_State * SRDEloader_State;

/**
 * External SRDEloader object representation.
 */
struct NAAAIM_SRDEloader
{
	/* External methods. */
	_Bool (*load)(const SRDEloader, const char *, _Bool);
	_Bool (*load_secs)(const SRDEloader, const char *, struct SGX_secs *, \
			   _Bool);
	_Bool (*load_memory)(const SRDEloader, const char *, size_t, _Bool);
	_Bool (*load_secs_memory)(const SRDEloader, const char *, size_t, \
				  struct SGX_secs *, _Bool);

	_Bool (*load_segments)(const SRDEloader, const SRDEenclave);
	_Bool (*load_layouts)(const SRDEloader, const SRDEenclave);

	_Bool (*get_sigstruct)(const SRDEloader, struct SGX_sigstruct *);
	_Bool (*get_attributes)(const SRDEloader, sgx_attributes_t *);

	void (*debug)(const SRDEloader, const _Bool);
	void (*dump)(const SRDEloader);
	void (*whack)(const SRDEloader);

	/* Private state. */
	SRDEloader_State state;
};


/* SGXMetadata constructor call. */
extern HCLINK SRDEloader NAAAIM_SRDEloader_Init(void);
#endif
