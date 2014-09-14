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
#include <string.h>

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
	STATE(S);

	_Bool retn = false;

        unsigned char digest[TCPA_SHA1_160_HASH_LEN];


	if ( S->poisoned )
		goto done;
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
	if ( !retn )
		S->poisoned = true;
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


	if ( S->poisoned )
		goto done;
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


	if ( S->poisoned )
		goto done;
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
	WHACK(pcr_input);

	if ( !retn )
		S->poisoned = true;
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

	TSS_RESULT result;

	TSS_FLAG secret_mode;

	TPM_NV_DATA_PUBLIC *nv_public = NULL;

	TSS_HNVSTORE nvram = 0;

	TSS_HPOLICY tpm_policy,
		    nvram_policy;
	

	if ( S->poisoned )
		goto done;
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

		result = Tspi_NV_WriteValue(nvram, offset, write_segment, \
					    write_ptr);
		if ( result != TSS_SUCCESS ) {
			fprintf(stderr, "Failed NVram write: %s\n", \
				Trspi_Error_String(result));
			goto done;
		}

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

	if ( !retn )
		S->poisoned = true;
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

	TSS_RESULT result = TSS_SUCCESS;

	TPM_NV_DATA_PUBLIC *nv_public = NULL;

	TSS_HNVSTORE nvram = 0;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	result = Tspi_Context_CreateObject(S->context, TSS_OBJECT_TYPE_NV, 0, \
					   &nvram);
	if ( result != TSS_SUCCESS )
		goto done;

	result = Tspi_TPM_GetCapability(S->tpm, TSS_TPMCAP_NV_INDEX,	\
					sizeof(index),			\
					(unsigned char *) &index,	\
					&length, &output);
	if ( result != TSS_SUCCESS ) {
		fprintf(stderr, "Failed capability for index: %d\n", index);
		goto done;
	}

	if ( (nv_public = malloc(sizeof(TPM_NV_DATA_PUBLIC))) == NULL )
		goto done;

	result = Trspi_UnloadBlob_NV_DATA_PUBLIC(&offset, output, NULL);
	if ( result != TSS_SUCCESS )
		goto done;
	if ( offset > length )
		goto done;

	offset = 0;
	result = Trspi_UnloadBlob_NV_DATA_PUBLIC(&offset, output, nv_public);
	if ( result != TSS_SUCCESS )
		goto done;

	result = Tspi_SetAttribUint32(nvram, TSS_TSPATTRIB_NV_INDEX, 0, index);
	if ( result != TSS_SUCCESS ) {
		fprintf(stdout, "Failed attribute for index: %d\n", index);
		goto done;
	}

	result = Tspi_NV_ReadValue(nvram, 0, &nv_public->dataSize, &nv_output);
	if ( result != TSS_SUCCESS )
		goto done;
	if ( !bufr->add(bufr, nv_output, nv_public->dataSize) )
		goto done;

	result = Tspi_Context_FreeMemory(S->context, output);
	if ( result != TSS_SUCCESS ) 
		goto done;
	result = Tspi_Context_CloseObject(S->context, nvram);
	if ( result != TSS_SUCCESS )
		goto done;
	     
	retn = true;


 done:
	if ( result != TSS_SUCCESS )
		fprintf(stderr, "%s[%s] error: %s\n", __FILE__, __func__, \
			Trspi_Error_String(result));

	if ( nv_output != NULL )
		free(nv_output);
	if ( nv_public != NULL ) {
		free(nv_public->pcrInfoRead.pcrSelection.pcrSelect);
		free(nv_public->pcrInfoWrite.pcrSelection.pcrSelect);
		free(nv_public);
	}

	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements the ability to remove an NVram region.
 *
 * \param this		A pointer to the TPM object whose NVRAM region is to
 *			be removed.
 *
 * \param index		The index number of the NVRAM region to be removed.
 *
 * \param pwd		A String object containing the user password which
 *			will authenticate the write to the NVram.
 *
 * \param key		A boolean object used to signal whether the contents
 *			of the key_bufr is a key or a byte sequence which is
 *			to be hashed to yield the authentication key.
 *
 * \param key_bufr	A Buffer object containing the data to be used in
 *			constructing the authentication key.
 *
 * \return	If an error is encountered while reading the NVRAM
 *		region a false value is returned.  If the read is
 *		successful a true value is returned.
 */

static _Bool nv_remove(CO(TPMcmd, this), uint32_t index, _Bool key, \
		       CO(Buffer, key_bufr))

{
	STATE(S);

	_Bool retn = false;

	TSS_FLAG secret_mode;

	TSS_HNVSTORE nvram = 0;

	TSS_HPOLICY tpm_policy,
		    nvram_policy;
	

	if ( S->poisoned )
		goto done;
	if ( (key_bufr == NULL) || key_bufr->poisoned(key_bufr) )
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


	if ( Tspi_SetAttribUint32(nvram, TSS_TSPATTRIB_NV_INDEX, 0, index) != \
	     TSS_SUCCESS )
		goto done;

	if ( Tspi_NV_ReleaseSpace(nvram) != TSS_SUCCESS )
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
 * This method implements the generation of a machine status quote
 * based on a nonce provided by the validating system.
 *
 * \param this	A pointer to the TPM object which will generate the
 *		nonce.
 *
 * \param uuid	A Buffer object containing the UUID of the attestation
 *		identity key.
 *
 * \param quote	A Buffer object which serves dual purposes.  When
 *		called this method expects the Buffer object to
 *		contain the nonce which will be used to generate the
 *		quote.  If generation of the quote is successful the
 *		object is reset and loaded with the generated quote.
 *
 * \return	If an error is encountered while generating the quote
 *		a false value is returned.  If the quote Buffer contains
 *		a valid quote a true value is returned.
 */

static _Bool quote(CO(TPMcmd, this), CO(Buffer, key_uuid), CO(Buffer, quote))

{
	STATE(S);

	_Bool retn = false;

	char *err = NULL;

	unsigned char *version_info,
		       all_zeros[] = TSS_WELL_KNOWN_SECRET;

	UINT32 version_length;

	TSS_RESULT result = TSS_SUCCESS;

	TSS_VALIDATION nonce;

	TSS_UUID *aik_uuid,
		 srk_uuid = {0, 0, 0, 0, 0, {0, 0, 0, 0, 0, 1}};

	TSS_HKEY srk,
		 quote_key;

	TSS_HPOLICY srk_policy;

	TSS_HPCRS pcr_set;


	nonce.ulExternalDataLength  = quote->size(quote);
	nonce.rgbExternalData = quote->get(quote);

	/* Load the attestation identity key via the storage root key. */
	result = Tspi_Context_LoadKeyByUUID(S->context, TSS_PS_TYPE_SYSTEM, \
					    srk_uuid, &srk);
	if ( result != TSS_SUCCESS ) {
		err = "SRK keyload";
		goto done;
	}

	result = Tspi_GetPolicyObject(srk, TSS_POLICY_USAGE, &srk_policy);
	if ( result != TSS_SUCCESS ) {
		err = "SRK policy creation";
		goto done;
	}

	result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1, \
				       sizeof(all_zeros), all_zeros);
	if ( result != TSS_SUCCESS ) {
		err = "SRK password set";
		goto done;
	}

	aik_uuid = (TSS_UUID *) key_uuid->get(key_uuid);
	result = Tspi_Context_LoadKeyByUUID(S->context, TSS_PS_TYPE_SYSTEM, \
					    *aik_uuid, &quote_key);
	if ( result != TSS_SUCCESS ) {
		err = "Loading AIK key";
		goto done;
	}


	/* Compute the platform configuration register status. */
	result =  Tspi_Context_CreateObject(S->context, TSS_OBJECT_TYPE_PCRS, \
					    TSS_PCRS_STRUCT_INFO_SHORT,       \
					    &pcr_set);
	if ( result != TSS_SUCCESS ) {
		err = "Creating PCR object.";
		goto done;
	}

	err = "Creating PCR";
	result = Tspi_PcrComposite_SelectPcrIndexEx(pcr_set, 10, \
						   TSS_PCRS_DIRECTION_RELEASE);
	if ( result != TSS_SUCCESS )
		goto done;
	result = Tspi_PcrComposite_SelectPcrIndexEx(pcr_set, 11, \
						   TSS_PCRS_DIRECTION_RELEASE);
	if ( result != TSS_SUCCESS )
		goto done;


	/* Obtain the quote. */
	result = Tspi_TPM_Quote2(S->tpm, quote_key, false, pcr_set, &nonce, \
				 &version_length, &version_info);
	if ( result != TSS_SUCCESS ) {
		err = "Obtaining quote";
		goto done;
	}
		
	quote->reset(quote);
	retn = quote->add(quote, nonce.rgbValidationData, \
			  nonce.ulValidationDataLength);

	result = Tspi_Context_FreeMemory(S->context, nonce.rgbData);
	if ( result != TSS_SUCCESS )
		goto done;
	result = Tspi_Context_FreeMemory(S->context, nonce.rgbValidationData);
	if ( result != TSS_SUCCESS )
		goto done;

 done:
	if ( result != TSS_SUCCESS )
		fprintf(stderr, "%s[%s] %s: %s\n", __FILE__, __func__, err, \
			Trspi_Error_String(result));

	return retn;
}


/**
 * External public method.
 *
 * This method implements the validation of a machine status quote which
 * has been previously generated by the ->quote method of this object.
 *
 * \param this		A pointer to the TPM object which will be used to
 *			verify the quote.
 *
 * \param key		A Buffer object containing the attestation identity
 *			public key.
 *
 * \param pcrref	A Buffer object which contains the PCR reference
 *			hash generated by the ->generate_quote method of
 *			this object.
 *
 * \param nonce		A Buffer object which contains the nonce on which
 *			the quote was generated.
 *
 * \param quote		A Buffer object which contains the quote which is to
 *			be evaluated.
 *
 * \return	If an error is encountered while verifying the machine
 *		qote a false value is returned.  If the quote Buffer
 *		contains a valid quote a true value is returned.
 */

static _Bool verify(CO(TPMcmd, this), CO(Buffer, key), CO(Buffer, pcrref), \
		    CO(Buffer, nonce), CO(Buffer, quote))

{
	STATE(S);

	_Bool retn = false;

	unsigned char key_bufr[1024];

	char *err = NULL;

	uint32_t type,
		 key_length = sizeof(key_bufr),
		 key_flags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048;

	TSS_RESULT result = TSS_SUCCESS;

	TPM_QUOTE_INFO2 *qinfo;
	
	TSS_HKEY pubkey;

	TSS_HHASH pcrhash;


	/* Insert nonce into quote. */
	if ( nonce->size(nonce) != sizeof(TPM_NONCE) ) {
		err = "Wrong nonce size";
		goto done;
	}
	qinfo = (TPM_QUOTE_INFO2 *) pcrref->get(pcrref);
	memcpy(&qinfo->externalData, nonce->get(nonce), sizeof(TPM_NONCE));


	/* Load public key from supplied Buffer. */
	result = Tspi_DecodeBER_TssBlob(key->size(key), key->get(key), &type, \
					&key_length, key_bufr);
	if ( result != TSS_SUCCESS ) {
		err = "Decoding AIK public key";
		goto done;
	}
	if ( type != TSS_BLOB_TYPE_PUBKEY ) {
		err = "Decoded key is not a public key";
		goto done;
	}

	result = Tspi_Context_CreateObject(S->context,			      \
					   TSS_OBJECT_TYPE_RSAKEY, key_flags, \
					   &pubkey);
	if ( result != TSS_SUCCESS ) {
		err = "Creating public key object";
		goto done;
	}

	result = Tspi_SetAttribData(pubkey, TSS_TSPATTRIB_KEY_BLOB,   \
				    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, \
				    key_length, key_bufr);
	if ( result != TSS_SUCCESS ) {
		err = "Loading public key";
		goto done;
	}

	/* Compute hash of quote to verify signature. */
	result = Tspi_Context_CreateObject(S->context, TSS_OBJECT_TYPE_HASH, \
					   TSS_HASH_SHA1, &pcrhash);
	if ( result != TSS_SUCCESS ) {
		err = "Creating hash object";
		goto done;
	}

	result = Tspi_Hash_UpdateHashValue(pcrhash, pcrref->size(pcrref), \
					   pcrref->get(pcrref));

	result = Tspi_Hash_VerifySignature(pcrhash, pubkey,    \
					   quote->size(quote), \
					   quote->get(quote));
	if ( result != TSS_SUCCESS ) {
		err = "Verifying signature";
		goto done;
	}

	retn = true;
	

 done:
	if ( result != TSS_SUCCESS )
		fprintf(stderr, "%s[%s] %s: %s\n", __FILE__, __func__, err, \
			Trspi_Error_String(result));
	return retn;
}


/**
 * External public method.
 *
 * This method implements the creation of a machine status quote.  A
 * machine status quote is the hash of a set of platform configuration
 * registers signed by an identity attestation key.
 *
 * \param this	A pointer to the TPM object which will generate the
 *		nonce.
 *
 * \param uuid	A Buffer object containing the UUID of the attestation
 *		identity key.
 *
 * \param quote A Buffer object which on input will contain the nonce to
 *		be used for the generation of the machine status quote.
 *		On return the none contains the hash of the platform
 *		configuration registers.
 *
 * \return	If an error is encountered while generating the machine
 *		status quote a false value is returned.  If the generation
 *		of the reference quote is successful the quote Buffer
 *		object contains the hash of the PCR register set.
 */

static _Bool generate_quote(CO(TPMcmd, this), CO(Buffer, key_uuid), \
			    CO(Buffer, quote))

{
	STATE(S);

	_Bool retn = false;

	char *err = NULL;

	unsigned char *version_info,
		      all_zeros[] = TSS_WELL_KNOWN_SECRET;

	UINT32 version_length;

	TSS_RESULT result = TSS_SUCCESS;

	TSS_VALIDATION nonce;

	TSS_UUID *aik_uuid,
		 srk_uuid = {0, 0, 0, 0, 0, {0, 0, 0, 0, 0, 1}};

	TSS_HKEY srk,
		 quote_key;

	TSS_HPOLICY srk_policy;

	TSS_HPCRS pcr_set;


	nonce.ulExternalDataLength  = quote->size(quote);
	nonce.rgbExternalData = quote->get(quote);

	/* Load the attestation identity key via the storage root key. */
	result = Tspi_Context_LoadKeyByUUID(S->context, TSS_PS_TYPE_SYSTEM, \
					    srk_uuid, &srk);
	if ( result != TSS_SUCCESS ) {
		err = "SRK keyload";
		goto done;
	}

	result = Tspi_GetPolicyObject(srk, TSS_POLICY_USAGE, &srk_policy);
	if ( result != TSS_SUCCESS ) {
		err = "SRK policy creation";
		goto done;
	}

	result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1, \
				       sizeof(all_zeros), all_zeros);
	if ( result != TSS_SUCCESS ) {
		err = "SRK password set";
		goto done;
	}

	aik_uuid = (TSS_UUID *) key_uuid->get(key_uuid);
	result = Tspi_Context_LoadKeyByUUID(S->context, TSS_PS_TYPE_SYSTEM, \
					    *aik_uuid, &quote_key);
	if ( result != TSS_SUCCESS ) {
		err = "Loading AIK key";
		goto done;
	}


	/* Compute the platform configuration register status. */
	result =  Tspi_Context_CreateObject(S->context, TSS_OBJECT_TYPE_PCRS, \
					    TSS_PCRS_STRUCT_INFO_SHORT,       \
					    &pcr_set);
	if ( result != TSS_SUCCESS ) {
		err = "Creating PCR object.";
		goto done;
	}

	err = "Creating PCR";
	result = Tspi_PcrComposite_SelectPcrIndexEx(pcr_set, 10, \
						   TSS_PCRS_DIRECTION_RELEASE);
	if ( result != TSS_SUCCESS )
		goto done;
	result = Tspi_PcrComposite_SelectPcrIndexEx(pcr_set, 11, \
						   TSS_PCRS_DIRECTION_RELEASE);
	if ( result != TSS_SUCCESS )
		goto done;


	/* Obtain the quote. */
	result = Tspi_TPM_Quote2(S->tpm, quote_key, false, pcr_set, &nonce, \
				 &version_length, &version_info);
	if ( result != TSS_SUCCESS ) {
		err = "Obtaining quote";
		goto done;
	}
		
	quote->reset(quote);
	retn = quote->add(quote, nonce.rgbData, nonce.ulDataLength);

	result = Tspi_Context_FreeMemory(S->context, nonce.rgbData);
	if ( result != TSS_SUCCESS )
		goto done;
	result = Tspi_Context_FreeMemory(S->context, nonce.rgbValidationData);
	if ( result != TSS_SUCCESS )
		goto done;


 done:
	if ( result != TSS_SUCCESS )
		fprintf(stderr, "%s[%s] %s: %s\n", __FILE__, __func__, err, \
			Trspi_Error_String(result));

	return retn;
}


/**
 * External public method.
 *
 * This method implements creation of an attestation identity key.
 *
 * \param this		A pointer to the TPM object which will be used to
 *			generate the identity key.
 *
 * \param key		A boolean value which specifies whether or not
 *			the pwd arguement which follows contains a
 *			raw password to be hashed or a key.
 *
 * \param key_bufr	A Buffer object containing either a secret key
 *			or a password to be hashed to yield the key.
 *
 * \param keycert	A Buffer object which on input will hold the
 *			public key used to encrypt the identity
 *			key certificate.  If this Buffer has a size of
 *			zero a 'throwaway' key is generated.  On return
 *			this Buffer object will contain the identity
 *			attestation certificate.
 *
 * \param uuid		A Buffer object which will be loaded with the UUID
 *			which is generated to index the key.
 *
 * \param aikpub	A Buffer object containing the public version of
 *			the identity key which is used to verify
 *			attestations make with this key.
 *
 * \return	If an error is encountered in generating the key a
 *		false value is returned.  If  the generation of the
 *		reference quote is successful a true value is returned.
 */

static _Bool generate_identity(CO(TPMcmd, this), _Bool key,		  \
			       CO(Buffer, key_bufr), CO(Buffer, keycert), \
			       CO(Buffer, uuid), CO(Buffer, aikpub))

{
	STATE(S);

	_Bool retn = false;

	char *err = NULL;

	unsigned char *bufr,
		      der_bufr[1024],
		      aik_label[] = {},
		      all_zeros[] = TSS_WELL_KNOWN_SECRET;

	uint32_t length,
		 der_length = sizeof(der_bufr);

	TSS_RESULT result = TSS_SUCCESS;

	TSS_FLAG secret_mode;

	TSS_HKEY srk,
		 cak,
		 aik;

	TSS_UUID *aik_uuid,
		 srk_uuid = TSS_UUID_SRK;

	TSS_HPOLICY srk_policy,
		    tpm_policy;


	/* Activate the storage root key. */
	result = Tspi_Context_LoadKeyByUUID(S->context, TSS_PS_TYPE_SYSTEM, \
					    srk_uuid, &srk);
	if ( result != TSS_SUCCESS ) {
		err = "SRK keyload";
		goto done;
	}

	result = Tspi_GetPolicyObject(srk, TSS_POLICY_USAGE, &srk_policy);
	if ( result != TSS_SUCCESS ) {
		err = "SRK policy creation";
		goto done;
	}

	result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1, \
				       sizeof(all_zeros), all_zeros);
	if ( result != TSS_SUCCESS ) {
		err = "SRK password set";
		goto done;
	}

	result = Tspi_GetPolicyObject(S->tpm, TSS_POLICY_USAGE, &tpm_policy);
	if ( result != TSS_SUCCESS ) {
		err = "Obtaining tpm policy";
		goto done;
	}

	secret_mode = key ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN;
	result = Tspi_Policy_SetSecret(tpm_policy, secret_mode,  \
				       key_bufr->size(key_bufr), \
				       key_bufr->get(key_bufr));
	if ( result != TSS_SUCCESS ) {
		err = "Setting TPM secret";
		goto done;
	}


	/* Create CA key */
	if ( keycert->size(keycert) == 0 ) {
		result = Tspi_Context_CreateObject(S->context,		   \
						   TSS_OBJECT_TYPE_RSAKEY, \
						   TSS_KEY_TYPE_LEGACY |   \
						   TSS_KEY_SIZE_2048, &cak);
		if ( result != TSS_SUCCESS ) {
			err = "Initializing CA key object.";
			goto done;
		}

		result = Tspi_Key_CreateKey(cak, srk, 0);
		if ( result != TSS_SUCCESS ) {
			err = "Creating CA key";
			goto done;
		}
	}


	/* Create the identity attestation key. */
	result = Tspi_Context_CreateObject(S->context,		   \
					   TSS_OBJECT_TYPE_RSAKEY, \
					   TSS_KEY_TYPE_IDENTITY | \
					   TSS_KEY_SIZE_2048, &aik);
	if ( result != TSS_SUCCESS ) {
		err = "Create AIK key object";
		goto done;
	}

	result = Tspi_TPM_CollateIdentityRequest(S->tpm, srk, cak, 0,	      \
						 aik_label, aik, TSS_ALG_AES, \
						 &length, &bufr);
	if ( result != TSS_SUCCESS ) {
		err = "Creating AIK key";
		goto done;
	}

	err = NULL;
	keycert->reset(keycert);
	if ( !keycert->add(keycert, bufr, length) )
		err = "Loading AIK cert request";

	result = Tspi_Context_FreeMemory(S->context, bufr);
	if ( err != NULL )
		goto done;
	if ( result != TSS_SUCCESS ) {
		err = "Freeing AIK key memory";
		goto done;
	}

	result = Tspi_GetAttribData(aik, TSS_TSPATTRIB_KEY_BLOB,      \
				    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, \
				    &length, &bufr);
	if ( result != TSS_SUCCESS ) {
		err = "Extracting AIK public key";
		goto done;
	}

	result = Tspi_EncodeDER_TssBlob(length, bufr, TSS_BLOB_TYPE_PUBKEY, \
					&der_length, der_bufr);
	if ( Tspi_Context_FreeMemory(S->context, bufr) != TSS_SUCCESS ) {
		err = "Freeing public key memory";
		goto done;
	}
	if ( result != TSS_SUCCESS ) {
		err = "Encoding AIK public key";
		goto done;
	}

	if ( !aikpub->add(aikpub, der_bufr, der_length) ) {
		err = "Loading AIK public key";
		goto done;
	}


	/* Create a UUID to index the identity. */
	result = Tspi_TPM_GetRandom(S->tpm, sizeof(TSS_UUID), \
				    (unsigned char **) &aik_uuid);
	if ( result != TSS_SUCCESS ) {
		err = "Getting random UUID";
		goto done;
	}

	aik_uuid->usTimeHigh &= 0x0fff;
	aik_uuid->usTimeHigh |= (4 << 12);
	aik_uuid->bClockSeqHigh &= 0x3f;
	aik_uuid->bClockSeqHigh |= 0x80;

	uuid->add(uuid, (unsigned char *) aik_uuid, sizeof(TSS_UUID));
	result = Tspi_Context_FreeMemory(S->context, \
					 (unsigned char *) aik_uuid);
	if ( result != TSS_SUCCESS ) {
		err = "Freeing UUID memory";
		goto done;
	}
	if ( uuid->poisoned(uuid) ) {
		err = "Loading UUID";
		goto done;
	}

	result = Tspi_GetAttribData(aik, TSS_TSPATTRIB_KEY_BLOB, \
				    TSS_TSPATTRIB_KEYBLOB_BLOB,  \
				    &length, &bufr);
	if ( result != TSS_SUCCESS ) {
		err = "Extracting AIK private key";
		goto done;
	}

	result = Tspi_Context_LoadKeyByBlob(S->context, srk, length, bufr, \
					    &aik);
	if ( Tspi_Context_FreeMemory(S->context, bufr) != TSS_SUCCESS ) {
		err = "Freeing public key memory";
		goto done;
	}
	if ( result != TSS_SUCCESS ) {
		err = "Loading private key";
		goto done;
	}

	aik_uuid = (TSS_UUID *) uuid->get(uuid);
	result = Tspi_Context_RegisterKey(S->context, aik,		 \
					  TSS_PS_TYPE_SYSTEM, *aik_uuid, \
					  TSS_PS_TYPE_SYSTEM, srk_uuid);
	if ( result != TSS_SUCCESS ) {
		err = "Registering AIK";
		goto done;
	}

	retn = true;


 done:
	if ( result != TSS_SUCCESS )
		fprintf(stderr, "%s[%s] %s: %s\n", __FILE__, __func__, err, \
			Trspi_Error_String(result));
	return retn;
}


/**
 * External public method.
 *
 * This method implements the display of keys which are registered in
 * system persistent storage
 *
 * \param this	A pointer to the TPM object whose keys are to be
 *		displayed.
 *
 * \return	No return value is defined.
 */

static void list_keys(CO(TPMcmd, this))

{
	STATE(S);

	TSS_RESULT result;

	uint32_t lp,
		 num_keys;

	Buffer key_uuid = NULL;

	TSS_KM_KEYINFO2 *keys;


	INIT(HurdLib, Buffer, key_uuid, goto done);

	result = Tspi_Context_GetRegisteredKeysByUUID2(S->context,	   \
						       TSS_PS_TYPE_SYSTEM, \
						       NULL, &num_keys, &keys);
	if ( result != TSS_SUCCESS) {
		fputs("Error requesting keys.\n", stderr);
		return;
	}

	for (lp= 0; lp < num_keys; ++lp) {
		if ( !key_uuid->add(key_uuid,				 \
				    (unsigned char *) &keys[lp].keyUUID, \
				    sizeof(TSS_UUID)) )
			goto done;
		fprintf(stdout, "Key %u: ",lp);
		key_uuid->print(key_uuid);
		key_uuid->reset(key_uuid);

		if ( !key_uuid->add(key_uuid,				      \
				    (unsigned char *) &keys[lp].parentKeyUUID,\
				    sizeof(TSS_UUID)) )
			goto done;
		fputs("\tParent: ", stdout);
		key_uuid->print(key_uuid);
		key_uuid->reset(key_uuid);

		fprintf(stdout, "\tAuthorization%sneeded.\n", \
			keys[lp].bAuthDataUsage ? " " : " not ");
		fputc('\n', stdout);
	}
		

 done:
	Tspi_Context_FreeMemory(S->context, (unsigned char *) keys);

	WHACK(key_uuid);
	
	return;
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
	this->nv_remove	= nv_remove;

	this->quote	     = quote;
	this->verify	     = verify;
	this->generate_quote = generate_quote;

	this->generate_identity = generate_identity;

	this->list_keys = list_keys;

	this->whack = whack;

	return this;
}
