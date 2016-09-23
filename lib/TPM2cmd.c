/** \file
 * This file provides the method implementations for an object which
 * implements various Trusted Platform Module Version 2 (TPM2) commands.
 * The current command set is as follows:
 *
 *     	Read the value of a platform configuration register.
 *      Extend the value of a platform configuration register.
 *	Read the contents of an NVRAM region.
 */

/**************************************************************************
 * (C)Copyright 2016, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */

/*
 * The following define configures the TSE library to build on POSIX
 * based systems.
 */
#define TPM_POSIX
#define TPM_BITFIELD_LE
#define TPM_TSS
#define TPM_ENCRYPT_SESSIONS_DEFAULT "0"
#define TPM_DEFAULT_INTERFACE_TYPE "dev"


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include <tse/tse.h>
#include <tse/tseproperties.h>
#include <tse/tseresponsecode.h>

#include "NAAAIM.h"
#include "TPM2cmd.h"

/* Object state extraction macro. */
#define STATE(var) CO(TPM2cmd_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TPM2cmd_OBJID)
#error Object identifier not defined.
#endif


/** TPM2cmd private state information. */
struct NAAAIM_TPM2cmd_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Size of the hash algorithm being used. */
	TPMI_ALG_HASH hash_type;

	/* TPM2 context. */
	TSE_CONTEXT *context;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_TPM2cmd_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(TPM2cmd_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TPM2cmd_OBJID;

	S->poisoned  = false;
	S->hash_type = TPM_ALG_SHA1;
	S->context   = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for setting up a TSPI and TPM2 context state.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static _Bool _init_tpm_state(CO(TPM2cmd_State, S)) {

	_Bool retn = false;


	if ( TSE_Create(&S->context) != 0 )
		ERR(goto done);

	retn = true;

 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements computation of the hash of the supplied
 * buffer.  The computed hash replaces the contents of the buffer.
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

static _Bool hash(CO(TPM2cmd, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL;

	Hash_In in;

	Hash_Out out;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;
	if ( bufr->size(bufr) > MAX_DIGEST_BUFFER )
		goto done;


	in.hashAlg = S->hash_type;
	in.hierarchy = hierarchy;

	in.data.t.size = bufr->size(bufr);
	memcpy(in.data.t.buffer, bufr->get(bufr), in.data.t.size);

	if ( TSE_Execute(S->context, (RESPONSE_PARAMETERS *) &out, \
			 (COMMAND_PARAMETERS *) &in, NULL, TPM_CC_Hash, \
			 TPM_RH_NULL, NULL, 0) != 0 )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, out.outHash.t.buffer, out.outHash.t.size) )
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

static _Bool pcr_read(CO(TPM2cmd, this), const TPMI_DH_PCR index, \
		      CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	TPM_RC tpm_retn;

	PCR_Read_In in;

	PCR_Read_Out out;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	in.pcrSelectionIn.count = 1;
	in.pcrSelectionIn.pcrSelections[0].hash = S->hash_type;
	in.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[index / 8] = \
		1 << (index % 8);

	tpm_retn = TSE_Execute(S->context, (RESPONSE_PARAMETERS *) &out, \
			       (COMMAND_PARAMETERS *) &in, NULL,	 \
			       TPM_CC_PCR_Read, TPM_RH_NULL, NULL, 0);
	if ( tpm_retn != 0 ) {
		const char *msg, *submsg, *num;
	      
		TSEResponseCode_toString(&msg, &submsg, &num, tpm_retn);
		fprintf(stderr, "TPM error, code=%08x, reason=%s,%s,%s\n", \
			tpm_retn, msg, submsg, num);
		goto done;
	}		

	if ( !bufr->add(bufr, out.pcrValues.digests[0].t.buffer, \
			out.pcrValues.digests[0].t.size) )
		ERR(goto done);
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
 *		the register.  The contents of the Buffer object
 *		will be first reduced to the current operative hash
 *		size and the resulting hash will be used for the
 *		extension operation.
 *
 * \return	If an error is encountered while extending the PCR
 *		register a false value is returned.  If a successful
 *		read occurs a true value is returned.
 */

static _Bool pcr_extend(CO(TPM2cmd, this), const uint32_t index, \
			CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	PCR_Extend_In in;

	Buffer pcr_input = NULL;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	INIT(HurdLib, Buffer, pcr_input, goto done);
	pcr_input->add_Buffer(pcr_input, bufr);
	if ( !hash(this, pcr_input) )
		goto done;

	in.digests.count = 1;
	in.digests.digests[0].hashAlg = S->hash_type;
	memcpy(&in.digests.digests[0].digest, pcr_input->get(pcr_input), \
	       pcr_input->size(pcr_input));

	if ( TSE_Execute(S->context, NULL, (COMMAND_PARAMETERS *) &in,	\
			 NULL, TPM_CC_PCR_Extend, TPM_RS_PW, NULL, 0,	\
			 TPM_RH_NULL, NULL, 0) != 0 )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !this->pcr_read(this, index, bufr) )
		ERR(goto done);
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
 * This method implements the definition of an NVram space.  This
 * function also implements an initial read of the space so that the
 * name is defined upon completion of the definition.  The NVram
 * space is created in the platform owner space.
 *
 * \param this	A pointer to the object whose NVram space is to be
 *		created.
 *
 * \param index	The index number of the region to be created.
 *
 * \param size	The size of the region to be created.
 *
 * \param auth	The authorization attributes which are to be applied.
 *		This value is OR'ed with TPMA_NVA_NO_DA by default.
 *
 * \param pwd   The object containing the password which is to be
 *		used to access the NRram location.  A null value is
 *		used to indicate that no password is to be used.
 *
 * \param pol	An object containing a policy to be applied.  A null
 *		value is used to indicate that no policy will be
 *		implemented for the location.
 *
 * \return	If an error is encountered during any phase of the
 *		NVram location creation a false value is returned.  If
 *		creation is successful a true value is returned.
 */

static _Bool nv_define(CO(TPM2cmd, this), const uint32_t index,	 \
		       const uint32_t size, const uint32_t auth, \
		       CO(Buffer, pwd), CO(Buffer, pol))

{
	STATE(S);

	_Bool retn = false;

	uint16_t name_type;

	char *lpwd = NULL;

	int rc;

	NV_DefineSpace_In nvdef;

	NV_ReadPublic_In pubin;

	NV_ReadPublic_Out pubout;

	TPMA_NV nvattr;


	if ( S->poisoned )
		goto done;
	if ( (pol != NULL) && pol->poisoned(pol) )
		goto done;
	if ( (pwd != NULL) && pwd->poisoned(pwd) )
		goto done;

	/* Add support for authorization password. */
	nvdef.auth.b.size = 0;

	/* Add support for authorization policy. */
	nvdef.publicInfo.t.nvPublic.authPolicy.t.size = 0;

#if 1
	nvdef.authHandle = TPM_RH_OWNER;
#else
	nvdef.authHandle = index;
#endif

	nvdef.publicInfo.t.nvPublic.nameAlg = S->hash_type;
	nvdef.publicInfo.t.nvPublic.nvIndex = index;
	nvdef.publicInfo.t.nvPublic.dataSize = size;

	nvattr.val  = TPMA_NVA_ORDINARY;
	nvattr.val |= auth;
	nvdef.publicInfo.t.nvPublic.attributes = nvattr;

	if ( pwd != NULL )
		lpwd = (char *) pwd->get(pwd);

	if ( (rc = TSE_Execute(S->context, NULL, (COMMAND_PARAMETERS *) &nvdef, \
			 NULL, TPM_CC_NV_DefineSpace, TPM_RS_PW, lpwd, 0, \
			       TPM_RH_NULL, NULL, 0)) != 0 ) {
		const char *msg, *submsg, *num;
		TSEResponseCode_toString(&msg, &submsg, &num, rc);
		fprintf(stderr, "%s: %s%s%s\n", __func__, msg, submsg, num);
		ERR(goto done);
	}


	/*
	 * Read the public definition in order to instantiate the name
	 * of the index.
	 */
	pubin.nvIndex = index;

	if ( TSE_Execute(S->context, (RESPONSE_PARAMETERS *) &pubout, \
			 (COMMAND_PARAMETERS *) &pubin, NULL, 	      \
			 TPM_CC_NV_ReadPublic, TPM_RH_NULL, NULL, 0) != 0 )
		ERR(goto done);

	if ( pubout.nvPublic.t.nvPublic.nameAlg != S->hash_type )
		ERR(goto done);

	memcpy(&name_type, pubout.nvName.t.name, sizeof(uint16_t));
	if ( ntohs(name_type) != S->hash_type )
		ERR(goto done);

	if ( pubout.nvPublic.t.nvPublic.nvIndex != index )
		ERR(goto done);

	if ( pubout.nvPublic.t.nvPublic.dataSize != size )
		ERR(goto done);
									     
	retn = true;

 done:
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
 * \param this	A pointer to the TPM2 object whose NVRAM region is to
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

static _Bool nv_read(CO(TPM2cmd, this), uint32_t index, CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	NV_ReadPublic_In pubin;

	NV_ReadPublic_Out pubout;

	NV_Read_In nvin;

	NV_Read_Out nvout;

	uint32_t a;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;

	/*
	 * Read the public definition in order to get the size of the
	 * index.
	 */
	pubin.nvIndex = index;

	if ( ( rc = TSE_Execute(S->context, (RESPONSE_PARAMETERS *) &pubout, \
				(COMMAND_PARAMETERS *) &pubin, NULL,	     \
				TPM_CC_NV_ReadPublic, TPM_RH_NULL, NULL, 0)) \
	     != 0 ) {
		const char *msg, *submsg, *num;
		TSEResponseCode_toString(&msg, &submsg, &num, rc);
		fprintf(stderr, "%s: %s%s%s\n", __func__, msg, submsg, num);
		ERR(goto done);
	}
	a = pubout.nvPublic.t.nvPublic.attributes.val;
	fprintf(stderr, "Attributes: 0x%08x\n", a);
	
	if ( a & TPMA_NVA_PPWRITE )
		fputs("\tPPWRITE\n", stderr);
	if ( a & TPMA_NVA_OWNERWRITE )
		fputs("\tOWNERWRITE\n", stderr);
	if ( a & TPMA_NVA_AUTHWRITE )
		fputs("\tAUTHWRITE\n", stderr);
	if ( a & TPMA_NVA_POLICYWRITE )
		fputs("\tPOLICYWRITE\n", stderr);
	if ( a & TPMA_NVA_COUNTER )
		fputs("\tCOUNTER\n", stderr);
	if ( a & TPMA_NVA_BITS )
		fputs("\tBITS\n", stderr);
	if ( a & TPMA_NVA_EXTEND )
		fputs("\tEXTEND\n", stderr);
	if ( a & TPMA_NVA_PIN_FAIL )
		fputs("\tPIN FAIL\n", stderr);
	if ( a & TPMA_NVA_POLICY_DELETE )
		fputs("\tPOLICY DELETE\n", stderr);
	if ( a & TPMA_NVA_WRITELOCKED )
		fputs("\tWRITELOCKED\n", stderr);
	if ( a & TPMA_NVA_WRITEALL )
		fputs("\tWRITEALL\n", stderr);
	if ( a & TPMA_NVA_WRITEDEFINE )
		fputs("\tWRITEDEFINE\n", stderr);
	if ( a & TPMA_NVA_WRITE_STCLEAR )
		fputs("\tWRITE STCLEAR\n", stderr);
	if ( a & TPMA_NVA_GLOBALLOCK )
		fputs("\tGLOBALLOCK\n", stderr);
	if ( a & TPMA_NVA_PPREAD )
		fputs("\tPPREAD\n", stderr);
	if ( a & TPMA_NVA_OWNERREAD )
		fputs("\tOWNERREAD\n", stderr);
	if ( a & TPMA_NVA_AUTHREAD )
		fputs("\tAUTHREAD\n", stderr);
	if ( a & TPMA_NVA_POLICYREAD )
		fputs("\tPOLICYREAD\n", stderr);
	if ( a & TPMA_NVA_NO_DA )
		fputs("\tNO DA\n", stderr);
	if ( a & TPMA_NVA_ORDERLY )
		fputs("\tORDERLY\n", stderr);
	if ( a & TPMA_NVA_CLEAR_STCLEAR )
		fputs("\tCLEAR STCLEAR\n", stderr);
	if ( a & TPMA_NVA_READLOCKED )
		fputs("\tREADLOCKED\n", stderr);
	if ( a & TPMA_NVA_WRITTEN )
		fputs("\tWRITTEN\n", stderr);
	if ( a & TPMA_NVA_PLATFORMCREATE )
		fputs("\tPLATFORMCREATE\n", stderr);
	if ( a & TPMA_NVA_READ_STCLEAR )
		fputs("\tREAD STCLEAR\n", stderr);

	/* Read the NVram index region. */
	nvin.authHandle = index;
	nvin.nvIndex	= index;
	nvin.offset	= 0;
	nvin.size	= pubout.nvPublic.t.nvPublic.dataSize;

	if ( TSE_Execute(S->context, (RESPONSE_PARAMETERS *) &nvout,	  \
			 (COMMAND_PARAMETERS *) &nvin, NULL,		  \
			 TPM_CC_NV_Read, TPM_RS_PW, NULL, 0, TPM_RH_NULL, \
			 NULL, 0) != 0 )
		ERR(goto done);

	if ( !bufr->add(bufr, nvout.data.t.buffer, nvout.data.t.size) )
		ERR(goto done);

	retn = true;

 done:
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
 * \param this		A pointer to the TPM2 object whose NVRAM region is
 *			to be written
 *
 * \param index		The index number of the NVRAM region to be written.
 *
 * \param bufr		A Buffer object which holds the content which will
 *			be written to the NVram.
 *
 * \param pwd		A String object containing the user password which
 *			will authenticate the write to the NVram.
 *
 * \return	If an error is encountered while reading teh NVRAM
 *		region a false value is returned.  If the read is
 *		successful a true value is returned.
 */

static _Bool nv_write(CO(TPM2cmd, this), uint32_t index, CO(Buffer, bufr), \
		      CO(Buffer, pwd))

{
	STATE(S);

	_Bool retn = false;

	char *lpwd = NULL;

	NV_Write_In nvin;


	if ( S->poisoned )
		goto done;
	if ( (bufr == NULL) || bufr->poisoned(bufr) )
		goto done;
	if ( (pwd != NULL) && pwd->poisoned(pwd) )
		goto done;


	nvin.authHandle = TPM_RH_OWNER;
	nvin.nvIndex	= index;
	nvin.offset	= 0;

	if ( bufr->size(bufr) > MAX_NV_BUFFER_SIZE )
		ERR(goto done);
	nvin.data.t.size = bufr->size(bufr);
	memcpy(nvin.data.t.buffer, bufr->get(bufr), bufr->size(bufr));

	if ( pwd != NULL )
		lpwd = (char *) pwd->get(pwd);

	if ( TSE_Execute(S->context, NULL, (COMMAND_PARAMETERS *) &nvin, \
			 NULL, TPM_CC_NV_Write, TPM_RS_PW, lpwd, 0,	 \
			 TPM_RH_NULL, NULL, 0) != 0 )
		ERR(goto done);

	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements the ability to remove an NVram region.
 *
 * \param this		A pointer to the TPM2 object whose NVRAM region is to
 *			be removed.
 *
 * \param index		The index number of the NVRAM region to be removed.
 *
 * \param pwd		A String object containing the user password which
 *			will authenticate the write to the NVram.
 *
 * \return	If an error is encountered while reading the NVRAM
 *		region a false value is returned.  If the read is
 *		successful a true value is returned.
 */

static _Bool nv_remove(CO(TPM2cmd, this), uint32_t index, CO(Buffer, pwd))

{
	STATE(S);

	_Bool retn = false;

	char *lpwd = NULL;

	NV_UndefineSpace_In nvin;


	if ( S->poisoned )
		goto done;
	if ( (pwd != NULL) && pwd->poisoned(pwd) )
		goto done;

	nvin.authHandle = TPM_RH_OWNER;
	nvin.nvIndex	= index;

	if ( pwd != NULL )
		lpwd = (char *) pwd->get(pwd);

	if ( TSE_Execute(S->context, NULL, (COMMAND_PARAMETERS *) &nvin,    \
			 NULL, TPM_CC_NV_UndefineSpace, TPM_RS_PW, lpwd, 0, \
			 TPM_RH_NULL, NULL, 0) != 0 )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


#if 0
/**
 * External public method.
 *
 * This method implements the generation of a machine status quote
 * based on a nonce provided by the validating system.
 *
 * \param this	A pointer to the TPM2 object which will generate the
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

static _Bool quote(CO(TPM2cmd, this), CO(Buffer, key_uuid), CO(Buffer, quote))

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


	if ( S->pcr == 0 ) {
		err = "No PCR mask set.";
		goto done;
	}

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


	/* Obtain the quote. */
	result = Tspi_TPM_Quote2(S->tpm, quote_key, false, S->pcr, &nonce, \
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
 * \param this		A pointer to the TPM2 object which will be used to
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

static _Bool verify(CO(TPM2cmd, this), CO(Buffer, key), CO(Buffer, pcrref), \
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
 * \param this	A pointer to the TPM2 object which will generate the
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

static _Bool generate_quote(CO(TPM2cmd, this), CO(Buffer, key_uuid), \
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


	if ( S->pcr == 0 ) {
		err = "No PCR mask set.";
		goto done;
	}

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


	/* Obtain the quote. */
	result = Tspi_TPM_Quote2(S->tpm, quote_key, false, S->pcr, &nonce, \
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
 * \param this		A pointer to the TPM2 object which will be used to
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

static _Bool generate_identity(CO(TPM2cmd, this), _Bool key,		  \
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
 * This method implements the creation of a composite PCR index object.
 * A composite PCR index value is used to specify machine state for
 * operations such as quoting the status of a machine or sealing an
 * encryption key to the machine state.
 *
 * \param this		A pointer to the TPM2 object which the PCR
 *			composite will be generated against.
 *
 * \param PCR ...	This function is variadic and takes a list
 *			of signed integers.  The list is terminated
 *			with a negative integer value.
 *
 * \return	If an error is encountered in generating the composite
 *		index a false value is returned.  If the composite
 *		was successfully created a true value is returned.
 */

static _Bool pcrmask(CO(TPMcmd, this), ...)

{
	STATE(S);

	_Bool retn = false;

	int pcr;

	va_list ap;

	TSS_RESULT rc;


	if ( S->poisoned )
		goto done;


	/* Acquire a fress PCR object. */
	if ( S->pcr != 0 ) {
		rc = Tspi_Context_CloseObject(S->context, S->pcr);
		if ( rc != TSS_SUCCESS )
			goto done;
	}
	rc = Tspi_Context_CreateObject(S->context,		   \
				       TSS_OBJECT_TYPE_PCRS,	   \
				       TSS_PCRS_STRUCT_INFO_SHORT, \
				       &S->pcr);
	if ( rc != TSS_SUCCESS )
		goto done;
		

	/* Create a composite mask over the specified registers. */
	va_start(ap, this);
	do {
		pcr = va_arg(ap, int);
		if ( (pcr >= 0) && (pcr < 24) ) {
			rc = Tspi_PcrComposite_SelectPcrIndexEx(S->pcr, pcr, \
						   TSS_PCRS_DIRECTION_RELEASE);
			if ( rc != TSS_SUCCESS )
				goto done;
		}
	} while ( pcr >= 0 );
	va_end(ap);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
}


/**
 * External public method.
 *
 * This method implements the ability to extract the public portion of
 * a key which is stored in system persistent storage.
 *
 * \param this	A pointer to the TPM object whose key is to be extracted.
 *
 * \param uuid	A Buffer object which will be loaded with the UUID of
 *		the key which is to be extracted.
 *
 * \param key	A Buffer object which will be loaded with the public
 *		portion of the key.
 *
 * \return	A false value is returned if extraction of the public
 *		key failed.  If the Buffer object contains a valid
 *		public key a true value is returned.
 */

static _Bool get_pubkey(CO(TPM2cmd, this), CO(Buffer, uuid), CO(Buffer, key))

{
	STATE(S);

	_Bool retn = false;

	char *err = NULL;

	unsigned char *bufr,
		      der_bufr[1024],
		      all_zeros[] = TSS_WELL_KNOWN_SECRET;

	uint32_t length,
		 der_length = sizeof(der_bufr);

	TSS_RESULT result = TSS_SUCCESS;

	TSS_UUID *key_uuid,
		 srk_uuid = {0, 0, 0, 0, 0, {0, 0, 0, 0, 0, 1}};

	TSS_HKEY srk,
		 pubkey;

	TSS_HPOLICY srk_policy;


	/* Load the desired key via the storage root key. */
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

	key_uuid = (TSS_UUID *) uuid->get(uuid);
	result = Tspi_Context_LoadKeyByUUID(S->context, TSS_PS_TYPE_SYSTEM, \
					    *key_uuid, &pubkey);
	if ( result != TSS_SUCCESS ) {
		err = "Loading key";
		goto done;
	}


	/* Extract the public portion of the key and ASN1 encode it. */
	result = Tspi_GetAttribData(pubkey, TSS_TSPATTRIB_KEY_BLOB,   \
				    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, \
				    &length, &bufr);
	if ( result != TSS_SUCCESS ) {
		err = "Extracting public key";
		goto done;
	}

	result = Tspi_EncodeDER_TssBlob(length, bufr, TSS_BLOB_TYPE_PUBKEY, \
					&der_length, der_bufr);
	if ( Tspi_Context_FreeMemory(S->context, bufr) != TSS_SUCCESS ) {
		err = "Freeing public key memory";
		goto done;
	}
	if ( result != TSS_SUCCESS ) {
		err = "Encoding public key";
		goto done;
	}

	if ( !key->add(key, der_bufr, der_length) ) {
		err = "Loading public key";
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
 * \param this	A pointer to the TPM2 object whose keys are to be
 *		displayed.
 *
 * \return	No return value is defined.
 */

static void list_keys(CO(TPM2cmd, this))

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
#endif


/**
 * External public method.
 *
 * This method implements the ability to select the primary hash type
 * which will be used by commands which are mediated through this
 * object.
 *
 * \param this	A pointer to the TPM2 object whose hash type is to
 *		be set.
 *
 * \parm type	The hash selector value.
 *
 * \return	A false value is returned to indicate that setting
 *		of the hash type failed.  A true value indicates the
 *		operation had succeeded.
 */

static _Bool set_hash(CO(TPM2cmd, this), const TPM2cmd_hash_type type)

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		ERR(goto done);

	switch ( type ) {
		case TPM2cmd_sha1:
			S->hash_type = TPM_ALG_SHA1;
			break;
		case TPM2cmd_sha256:
			S->hash_type = TPM_ALG_SHA256;
			break;
		default:
			ERR(goto done);
	}

	retn = true;

 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the ability to decode an error return code
 * from a TPM2 device and print the corresponding human readable
 * message.
 *
 * \param this	A pointer to the TPM2 object.
 *
 * \param error	The error code to be coded.
 *
 * \return	No return value is defined.
 */

static void get_error(CO(TPM2cmd, this), const uint32_t error)

{
	const char *message,
		   *sub_message,
		   *number;
	      
	TSEResponseCode_toString(&message, &sub_message, &number, error);
	fprintf(stdout, "TPM error, code=%08x, reason=%s,%s,%s\n", \
		error, message, sub_message, number);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a TPM2cmd object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TPM2cmd, this))

{
	STATE(S);


	TSE_Delete(S->context);

	S->root->whack(S->root, this, S);
	return;
}

	
/**
 * External constructor call.
 *
 * This function implements a constructor call for a TPM2cmd object.
 *
 * \return	A pointer to the initialized TPM2cmd.  A null value
 *		indicates an error was encountered in object generation.
 */

extern TPM2cmd NAAAIM_TPM2cmd_Init(void)

{
	auto Origin root;

	auto TPM2cmd this = NULL;

	auto struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TPM2cmd);
	retn.state_size   = sizeof(struct NAAAIM_TPM2cmd_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TPM2cmd_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize a TPM2 context. */
	_init_tpm_state(this->state);

	/* Method initialization. */
	this->hash = hash;

	this->pcr_read	 = pcr_read;
	this->pcr_extend = pcr_extend;

	this->nv_define = nv_define;
	this->nv_read	= nv_read;
	this->nv_write	= nv_write;
	this->nv_remove	= nv_remove;

#if 0
	this->quote	     = quote;
	this->verify	     = verify;
	this->generate_quote = generate_quote;

	this->generate_identity = generate_identity;

	this->pcrmask = pcrmask;

	this->get_pubkey = get_pubkey;
	this->list_keys  = list_keys;
#endif
	this->set_hash  = set_hash;
	this->get_error = get_error;

	this->whack = whack;

	return this;
}
