/** \file
 * This file contains definitions for an object which is used to
 * manipulate the Software Guard Extensions (SGX) metadata which is
 * integrated in the form of an ELF section into an SGX enclave shared
 * object file.
 */

/**************************************************************************
 * (C)Copyright 2016, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

#ifndef NAAAIM_SGXmetadata_HEADER
#define NAAAIM_SGXmetadata_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SGXmetadata * SGXmetadata;

typedef struct NAAAIM_SGXmetadata_State * SGXmetadata_State;

/**
 * External SGXMetadata object representation.
 */
struct NAAAIM_SGXmetadata
{
	/* External methods. */
	_Bool (*load)(const SGXmetadata, const char *);
	void (*patch_enclave)(const SGXmetadata, uint8_t *);
	_Bool (*compute_attributes)(const SGXmetadata, _Bool);

	_Bool (*get_secs)(const SGXmetadata, struct SGX_secs *);
	_Bool (*get_sigstruct)(const SGXmetadata, struct SGX_sigstruct *);
	_Bool (*get_attributes)(const SGXmetadata, sgx_attributes_t *);

	_Bool (*load_layouts)(const SGXmetadata, const SGXenclave);

	void (*debug)(const SGXmetadata, const _Bool);
	void (*dump)(const SGXmetadata);
	void (*whack)(const SGXmetadata);

	/* Private state. */
	SGXmetadata_State state;
};


/* SGXMetadata constructor call. */
extern SGXmetadata NAAAIM_SGXmetadata_Init(void);

#endif
