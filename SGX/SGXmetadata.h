/** \file
 * This file contains definitions for an object which is used to
 * manipulate the Software Guard Extensions (SGX) metadata which is
 * integrated in the form of an ELF section into an SGX enclave shared
 * object file.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
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
	_Bool (*load_memory)(const SGXmetadata, char *, const size_t);
	void (*patch_enclave)(const SGXmetadata, uint8_t *);
	_Bool (*compute_attributes)(const SGXmetadata, _Bool);

	_Bool (*get_secs)(const SGXmetadata, struct SGX_secs *);
	_Bool (*get_sigstruct)(const SGXmetadata, struct SGX_sigstruct *);
	_Bool (*get_attributes)(const SGXmetadata, sgx_attributes_t *);
	_Bool (*get_version)(const SGXmetadata, uint32_t *, uint32_t *);

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
