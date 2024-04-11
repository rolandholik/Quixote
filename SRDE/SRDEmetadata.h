/** \file
 * This file contains definitions for an object which is used to
 * manipulate the Software Guard Extensions (SGX) metadata which is
 * integrated in the form of an ELF section into an SGX enclave shared
 * object file.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#ifndef NAAAIM_SRDEmetadata_HEADER
#define NAAAIM_SRDEmetadata_HEADER


/* Object type definitions. */
typedef struct NAAAIM_SRDEmetadata * SRDEmetadata;

typedef struct NAAAIM_SRDEmetadata_State * SRDEmetadata_State;

/**
 * External SGXMetadata object representation.
 */
struct NAAAIM_SRDEmetadata
{
	/* External methods. */
	_Bool (*load)(const SRDEmetadata, const char *);
	_Bool (*load_memory)(const SRDEmetadata, char *, const size_t);
	void (*patch_enclave)(const SRDEmetadata, uint8_t *);
	_Bool (*compute_attributes)(const SRDEmetadata, _Bool);

	_Bool (*get_secs)(const SRDEmetadata, struct SGX_secs *);
	_Bool (*get_sigstruct)(const SRDEmetadata, struct SGX_sigstruct *);
	_Bool (*get_attributes)(const SRDEmetadata, sgx_attributes_t *);
	_Bool (*get_version)(const SRDEmetadata, uint32_t *, uint32_t *);

	_Bool (*load_layouts)(const SRDEmetadata, const SRDEenclave);

	void (*debug)(const SRDEmetadata, const _Bool);
	void (*dump)(const SRDEmetadata);
	void (*whack)(const SRDEmetadata);

	/* Private state. */
	SRDEmetadata_State state;
};


/* SRDEMetadata constructor call. */
extern HCLINK SRDEmetadata NAAAIM_SRDEmetadata_Init(void);
#endif
