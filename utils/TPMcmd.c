/** \file
 * This file provides the method implementations for an object which
 * implements various Trusted Platform Module (TPM) commands.  The
 * current command set is as follows:
 *
 *     	Read the value of a platform configuration register.
 *      Extend the value of a platform configuration register.
 *	Read the contents of an NVRAM region.
 */

/**************************************************************************
 * (C)Copyright 2014, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <tss/tspi.h>
#include <trousers/trousers.h>

#include "NAAAIM.h"
#include "TPMcmd.h"

/* Object state extraction macro. */
#define STATE(var) CO(TPMcmd_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TPMcmd_OBJID)
#error Object identifier not defined.
#endif


/** TPMcmd private state information. */
struct NAAAIM_TPMcmd_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* TSPI api context. */
	TSS_HCONTEXT context;

	/* TPM context. */
	TSS_HTPM tpm;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_TPMcmd_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(TPMcmd_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TPMcmd_OBJID;

	S->poisoned = false;

	S->context  = 0;
	S->tpm	    = 0;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for setting up a TSPI and TPM context state.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static _Bool _init_tpm_state(CO(TPMcmd_State, S)) {

	_Bool retn = false;

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TPMcmd_OBJID;


	if ( Tspi_Context_Create(&S->context) != TSS_SUCCESS )
		goto done;
	if ( Tspi_Context_Connect(S->context, NULL) != TSS_SUCCESS )
		goto done;
	if ( Tspi_Context_GetTpmObject(S->context, &S->tpm) != TSS_SUCCESS)
		goto done;

	retn = true;

 done:
	return retn;
}




/**
 * External public method.
 *
 * This method implements computation of the SHA160 hash of the
 * supplied buffer.  The computed hash replaces the contents of the
 * buffer.
 *
 * \param this	A pointer to the object on which a hash is to be
 *		computed.
 *
 * \param bufr	The Buffer object which the hash is to be computed over.
 *
 * \return	If an error is encountered while creating the hash a
 *		a false value is returned.  If the hashing is successful
 *		a true value is returned.
 */

static _Bool hash(CO(TPMcmd, this), CO(Buffer, bufr))

{
	_Bool retn = false;

        unsigned char digest[TCPA_SHA1_160_HASH_LEN];


	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	if ( Trspi_Hash(TSS_HASH_SHA1, bufr->size(bufr), bufr->get(bufr), \
			digest) != TSS_SUCCESS )
		goto done;

	bufr->reset(bufr);
	if ( !bufr->add(bufr, digest, TCPA_SHA1_160_HASH_LEN) )
		goto done;
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements reading of a single platform configuration
 * register.
 *
 * \param this	A pointer to the object whose PCR is to be read.
 *
 * \param index	The index number of the register to be read.
 *
 * \param bufr	The Buffer object which the value of the register is
 *		to be loaded into.
 *
 * \return	If an error is encountered while reading the PCR
 *		register a false value is returned.  If a successful
 *		read occurs a true value is returned.
 */

static _Bool pcr_read(CO(TPMcmd, this), const uint32_t index, CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	uint32_t length;

	unsigned char *output;


	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	if ( Tspi_TPM_PcrRead(S->tpm, index, &length, &output) != TSS_SUCCESS )
		goto done;
	if ( !bufr->add(bufr, output, length) )
		goto done;

	if ( Tspi_Context_FreeMemory(S->context, output) != TSS_SUCCESS )
		goto done;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements extending the contents of a single platform
 * configuration register.
 *
 * \param this	A pointer to the object whose PCR is to be extended.
 *
 * \param index	The index number of the register to be extended.
 *
 * \param bufr	A Buffer object whose contents will be used to extend
 *		the register.
 *
 * \return	If an error is encountered while extending the PCR
 *		register a false value is returned.  If a successful
 *		read occurs a true value is returned.
 */

static _Bool pcr_extend(CO(TPMcmd, this), const uint32_t index, \
			CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	uint32_t length;

	unsigned char *output;

	Buffer pcr_input = NULL;


	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	INIT(HurdLib, Buffer, pcr_input, goto done);
	pcr_input->add_Buffer(pcr_input, bufr);
	if ( !hash(this, pcr_input) )
		goto done;

	if ( Tspi_TPM_PcrExtend(S->tpm, index, pcr_input->size(pcr_input), \
				pcr_input->get(pcr_input), NULL, &length,  \
				&output) != TSS_SUCCESS )
		goto done;

	bufr->reset(bufr);
	if ( !bufr->add(bufr, output, length) )
		goto done;

	if ( Tspi_Context_FreeMemory(S->context, output) != TSS_SUCCESS )
		goto done;
	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;
	WHACK(pcr_input);

	return retn;
}


/**
 * External public method.
 *
 * This method implements writing the contents of a specified NVRAM
 * location.
 *
 * \param this		A pointer to the TPM object whose NVRAM region is to
 *			be written
 *
 * \param index		The index number of the NVRAM region to be written.
 *
 * \param pwd		A String object containing the user password which
 *			will authenticate the write to the NVram.
 *
 * \param bufr		A Buffer object which holds the content which will
 *			be written to the NVram.
 *
 * \param key		A boolean object used to signal whether the contents
 *			of the key_bufr is a key or a byte sequence which is
 *			to be hashed to yield the authentication key.
 *
 * \param key_bufr	A Buffer object containing the data to be used in
 *			constructing the authentication key.
 *
 * \return	If an error is encountered while reading teh NVRAM
 *		region a false value is returned.  If the read is
 *		successful a true value is returned.
 */

static _Bool nv_write(CO(TPMcmd, this), uint32_t index, CO(Buffer, bufr), \
		      _Bool key, CO(Buffer, key_bufr))

{
	STATE(S);

	_Bool retn = false;

	uint32_t length;

	uint64_t offset = 0;

	unsigned char *output,
		      *write_ptr,
		      *nv_output = NULL;

	size_t write_size,
	       write_segment;

	TSS_FLAG secret_mode;

	TPM_NV_DATA_PUBLIC *nv_public = NULL;

	TSS_HNVSTORE nvram = 0;

	TSS_HPOLICY tpm_policy,
		    nvram_policy;
	

	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	if ( Tspi_Context_CreateObject(S->context, TSS_OBJECT_TYPE_NV, 0, \
				       &nvram) != TSS_SUCCESS )
		goto done;

	secret_mode = key ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN;

	if ( Tspi_GetPolicyObject(S->tpm, TSS_POLICY_USAGE, &tpm_policy) !=
	     TSS_SUCCESS )
		goto done;
	if ( Tspi_Policy_SetSecret(tpm_policy, secret_mode,  \
				   key_bufr->size(key_bufr), \
				   key_bufr->get(key_bufr)) != TSS_SUCCESS )
		goto done;

	if ( Tspi_Context_CreateObject(S->context, TSS_OBJECT_TYPE_POLICY, \
				       TSS_POLICY_USAGE, &nvram_policy) != \
	     TSS_SUCCESS )
		goto done;
	if ( Tspi_Policy_SetSecret(nvram_policy, secret_mode,  \
				   key_bufr->size(key_bufr),   \
				   key_bufr->get(key_bufr)) != TSS_SUCCESS )
		goto done;

	if ( Tspi_Policy_AssignToObject(nvram_policy, nvram) != TSS_SUCCESS )
		goto done;


	/* Get NVram common area. */
	if ( Tspi_TPM_GetCapability(S->tpm, TSS_TPMCAP_NV_INDEX,	     \
				    sizeof(index), (unsigned char *) &index, \
				    &length, &output) != TSS_SUCCESS )
		goto done;

	if ( (nv_public = malloc(sizeof(TPM_NV_DATA_PUBLIC))) == NULL )
		goto done;

	if ( Trspi_UnloadBlob_NV_DATA_PUBLIC(&offset, output, NULL) != \
	     TSS_SUCCESS )
		goto done;
	if ( offset > length )
		goto done;

	offset = 0;
	if ( Trspi_UnloadBlob_NV_DATA_PUBLIC(&offset, output, nv_public) != \
	     TSS_SUCCESS )
		goto done;

	if ( bufr->size(bufr) > nv_public->dataSize )
		goto done;

	if ( Tspi_SetAttribUint32(nvram, TSS_TSPATTRIB_NV_INDEX, 0, index) != \
	     TSS_SUCCESS )
		goto done;


	/* Output to area in 1k chunk sizes at max. */
	offset	   = 0;
	write_size = bufr->size(bufr);
	write_ptr  = bufr->get(bufr);

	while ( write_size > 0 ) {
		write_segment = (write_size > 1024) ? 1024 : write_size;

		if ( Tspi_NV_WriteValue(nvram, offset, write_segment, \
					write_ptr) != TSS_SUCCESS )
			goto done;

		write_size -= write_segment;
		offset	   += write_segment;
		write_ptr  += write_segment;
	}

	if ( Tspi_Context_FreeMemory(S->context, output) != TSS_SUCCESS ) 
		goto done;
	if ( Tspi_Context_CloseObject(S->context, nvram) != TSS_SUCCESS )
		goto done;
	     
	retn = true;


 done:
	if ( nv_output != NULL )
		free(nv_output);
	if ( nv_public != NULL ) {
		free(nv_public->pcrInfoRead.pcrSelection.pcrSelect);
		free(nv_public->pcrInfoWrite.pcrSelection.pcrSelect);
		free(nv_public);
	}

	return retn;
}


/**
 * External public method.
 *
 * This method implements reading the contents of a specified NVRAM
 * location.
 *
 * \param this	A pointer to the TPM object whose NVRAM region is to
 *		be read
 *
 * \param index	The index number of the NVRAM region to be read
 *
 * \param bufr	A Buffer object which the region is to be read into.
 *
 * \return	If an error is encountered while reading teh NVRAM
 *		region a false value is returned.  If the read is
 *		successful a true value is returned.
 */

static _Bool nv_read(CO(TPMcmd, this), uint32_t index, CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	uint32_t length;

	uint64_t offset = 0;

	unsigned char *output,
		      *nv_output = NULL;

	TPM_NV_DATA_PUBLIC *nv_public = NULL;

	TSS_HNVSTORE nvram = 0;


	if ( Tspi_Context_CreateObject(S->context, TSS_OBJECT_TYPE_NV, 0, \
				       &nvram) != TSS_SUCCESS )
		goto done;

	if ( Tspi_TPM_GetCapability(S->tpm, TSS_TPMCAP_NV_INDEX,	     \
				    sizeof(index), (unsigned char *) &index, \
				    &length, &output) != TSS_SUCCESS )
		goto done;

	if ( (nv_public = malloc(sizeof(TPM_NV_DATA_PUBLIC))) == NULL )
		goto done;

	if ( Trspi_UnloadBlob_NV_DATA_PUBLIC(&offset, output, NULL) != \
	     TSS_SUCCESS )
		goto done;
	if ( offset > length )
		goto done;

	offset = 0;
	if ( Trspi_UnloadBlob_NV_DATA_PUBLIC(&offset, output, nv_public) != \
	     TSS_SUCCESS )
		goto done;

	if ( Tspi_SetAttribUint32(nvram, TSS_TSPATTRIB_NV_INDEX, 0, index) != \
	     TSS_SUCCESS )
		goto done;

	if ( Tspi_NV_ReadValue(nvram, 0, &nv_public->dataSize, &nv_output) != \
	     TSS_SUCCESS )
		goto done;
	if ( !bufr->add(bufr, nv_output, nv_public->dataSize) )
		goto done;

	if ( Tspi_Context_FreeMemory(S->context, output) != TSS_SUCCESS ) 
		goto done;
	if ( Tspi_Context_CloseObject(S->context, nvram) != TSS_SUCCESS )
		goto done;
	     
	retn = true;


 done:
	if ( nv_output != NULL )
		free(nv_output);
	if ( nv_public != NULL ) {
		free(nv_public->pcrInfoRead.pcrSelection.pcrSelect);
		free(nv_public->pcrInfoWrite.pcrSelection.pcrSelect);
		free(nv_public);
	}

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a TPMcmd object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TPMcmd, this))

{
	STATE(S);

	Tspi_Context_FreeMemory(S->context, NULL);
	if ( S->context != 0 )
		Tspi_Context_Close(S->context);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a TPMcmd object.
 *
 * \return	A pointer to the initialized TPMcmd.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TPMcmd NAAAIM_TPMcmd_Init(void)

{
	auto Origin root;

	auto TPMcmd this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TPMcmd);
	retn.state_size   = sizeof(struct NAAAIM_TPMcmd_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TPMcmd_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize a TPM context. */
	_init_tpm_state(this->state);

	/* Method initialization. */
	this->hash = hash;

	this->pcr_read	 = pcr_read;
	this->pcr_extend = pcr_extend;

	this->nv_write	= nv_write;
	this->nv_read	= nv_read;

	this->whack = whack;

	return this;
}
