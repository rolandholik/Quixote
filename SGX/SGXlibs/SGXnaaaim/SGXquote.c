/** \file
 * This file implements methods which encapsulate the OCALL's needed
 * to implement remote attestation quote processing via a SGXquote
 * object running in untrusted userspace.
 */

/*
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 */


/* Local defines. */


/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXquote.h"


/* Object state extraction macro. */
#define STATE(var) CO(SGXquote_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SGXquote_OBJID)
#error Object identifier not defined.
#endif


/** SGXquote private state information. */
struct NAAAIM_SGXquote_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Untrusted instance. */
	unsigned int instance;

	/* Object status. */
	_Bool poisoned;

	/* Quoting enclave target information. */
	struct SGX_targetinfo qe_target_info;
};


/**
 * Internal private function.
 *
 * This method is responsible for marshalling arguements and generating
 * the OCALL for the external methods call.
 *
 * \param ocp	A pointer to the data structure which is used to
 *		marshall the arguements into and out of the OCALL.
 *
 * \return	An integer value is used to indicate the status of
 *		the SGX call.  A value of zero indicate there was no
 *		error while a non-zero value, particularly negative
 *		indicates an error occurred in the call.  The return
 *		value from the external object is embedded in the
 *		data marshalling structure.
 */

static int sgxquote_ocall(struct SGXquote_ocall *ocall)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	void *ap;

	size_t quote_token_size,
	       pce_token_size,
	       epid_blob_size,
	       arena_size = sizeof(struct SGXquote_ocall);

	struct SGXquote_ocall *ocp = NULL;


	/* Verify arguements and set size of arena. */
	if ( ocall->ocall == SGXquote_init ) {
		quote_token_size = strlen(ocall->quote_token) + 1;
		if ( !sgx_is_within_enclave(ocall->quote_token, \
					    quote_token_size) )
			goto done;
		arena_size += quote_token_size;

		pce_token_size = strlen(ocall->pce_token) + 1;
		if ( !sgx_is_within_enclave(ocall->pce_token, \
					    pce_token_size) )
			goto done;
		arena_size += pce_token_size;

		epid_blob_size = strlen(ocall->epid_blob) + 1;
		if ( !sgx_is_within_enclave(ocall->epid_blob, \
					    epid_blob_size) )
			goto done;
		arena_size += epid_blob_size;
	}

	if ( ocall->ocall == SGXquote_generate_report ) {
		if ( !sgx_is_within_enclave(ocall->arena, ocall->bufr_size) )
			goto done;
		arena_size += ocall->bufr_size;
	}


	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena and pointers to it. */
	if ( ocall->ocall == SGXquote_init ) {
		ap = ocp->arena;

		memcpy(ap, ocall->quote_token, quote_token_size);
		ocp->quote_token = ap;
		ap += quote_token_size;

		memcpy(ap, ocall->pce_token, pce_token_size);
		ocp->pce_token = ap;
		ap += pce_token_size;

		memcpy(ap, ocall->epid_blob, epid_blob_size);
		ocp->epid_blob = ap;
	}

	if ( ocall->ocall == SGXquote_generate_report )
		memcpy(ocp->arena, ocall->bufr, ocall->bufr_size);


	/* Call the SGX duct manager. */
	if ( (status = sgx_ocall(3, ocp)) == 0 ) {
		retn = true;
		*ocall = *ocp;
	}


 done:
	sgx_ocfree();

	if ( status != 0 )
		return status;
	if ( !retn )
		return SGX_ERROR_UNEXPECTED;
	return 0;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SGXquote_State
 * structure which holds state information for each instantiated object.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(SGXquote_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SGXquote_OBJID;


	S->poisoned = false;
	S->instance = 0;

	return;
}


/**
 * External public method.
 *
 * This method implements the OCALL which initializes the object
 * in untrusted userspace.
 *
 * \param this		A pointer to the quoting object to be initialized.
 *
 * \param quote_token	A character pointer to a null-terminated buffer
 *			containing the name of the file that contains
 *			the initialization token for the quoting enclave.
 *
 * \param pce_token	A character pointer to a null-terminated buffer
 *			containing the name of the file that contains
 *			the initialization token for the PCE enclave.
 *
 * \param epid_blob	The name of the file containing the EPID
 *			blob.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool init(CO(SGXquote, this), CO(char *, quote_token), \
		  CO(char *, pce_token), CO(char *, epid_blob))

{
	STATE(S);

	_Bool retn = false;

	struct SGXquote_ocall ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_init;
	ocall.instance	= S->instance;

	ocall.quote_token = (char *) quote_token;
	ocall.pce_token	  = (char *) pce_token;
	ocall.epid_blob	  = (char *) epid_blob;

	if ( sgxquote_ocall(&ocall) != 0 )
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
 * This method implements the OCALL which is used to generate an
 * enclave quote for remote attestation.
 *
 * \param this		A pointer to the quoting object to be
 *			initialized.
 *
 * \param report	A pointer to to the enclave report that is to
 *			be attested.
 *
 * \param spid		The service provider identity to be used for
 *			the quote.
 *
 * \param nonce		The random nonce to be used for the quote.
 *
 * \param quote		The object which the binary quote is to be
 *			loaded into.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the initialization of the quote.  A false
 *		value indicates an error occurred while a true
 *		value indicates the quote was successfully initialized.
 */

static _Bool generate_quote(CO(SGXquote, this),				 \
			    struct SGX_report *report, CO(Buffer, spid), \
			    CO(Buffer, nonce), CO(Buffer, quote))

{
	STATE(S);

	_Bool retn = false;

	struct SGXquote_ocall ocall;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( spid->poisoned(spid) )
		ERR(goto done);
	if ( spid->size(spid) != 16 )
		ERR(goto done);
	if ( nonce->poisoned(nonce) )
		ERR(goto done);
	if ( nonce->size(nonce) != 16 )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_generate_quote,
	ocall.instance	= S->instance;

	ocall.report = *report;
	memcpy(ocall.spid, spid->get(spid), spid->size(spid));
	memcpy(ocall.nonce, nonce->get(nonce), nonce->size(nonce));

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	if ( !quote->add(quote, ocall.bufr, ocall.bufr_size) )
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
 * This method implements the OCALL which implements the generation of
 * an attestation requote on an enclave quote.
 *
 * \param this		A pointer to the quoting object to be
 *			initialized.
 *
 * \param quote		The object which contains the quote which is
 *			to be verifed by the authentication servers.
 *
 * \param report	The object that will be loaded with the report
 *			that is returned.
 *
 * \return	A boolean value is returned to indicate the
 *		status of the report generation.  A false value indicates
 *		an error occurred while a true value indicates the report
 *		was successfully generated.
 */

static _Bool generate_report(CO(SGXquote, this), CO(Buffer, quote), \
			     CO(String, report))

{
	STATE(S);

	_Bool retn = false;

	Buffer bufr = NULL;

	struct SGXquote_ocall ocall;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( quote->poisoned(quote) )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_generate_report,
	ocall.instance	= S->instance;

	ocall.bufr	= quote->get(quote);
	ocall.bufr_size = quote->size(quote);

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, ocall.bufr, ocall.bufr_size) )
		ERR(goto done);
	if ( !report->add(report, (char *) bufr->get(bufr)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return true;
}


/**
 * External public method.
 *
 * This method implements the OCALL which requests access to the
 * target information for the quoting enclave.
 *
 * \param this	A pointer to the object whose quoting enclave
 *		information is to be returned.
 *
 * \return	A pointer to the target structure is returned.  This
 *		may contain all null values if the object has not
 *		been initialized.
 */

static struct SGX_targetinfo * get_qe_targetinfo(CO(SGXquote, this))

{
	STATE(S);

	_Bool retn = false;

	struct SGXquote_ocall ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call the untrusted object implementation. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));

	ocall.ocall	= SGXquote_get_qe_targetinfo;
	ocall.instance	= S->instance;

	if ( sgxquote_ocall(&ocall) != 0 )
		ERR(goto done);

	S->qe_target_info = *ocall.qe_target_info;
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return &S->qe_target_info;
}


/**
 * External public method.
 *
 * This method implements the OCALL which requests destruction of
 * the userspace instance of the SGXquote object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXquote, this))

{
	STATE(S);

	struct SGXquote_ocall ocall;


	/* Release implementation object. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));
	ocall.ocall    = SGXquote_whack;
	ocall.instance = S->instance;
	sgxquote_ocall(&ocall);


	/* Destroy resources. */
	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SGXquote object.
 *
 * \return	A pointer to the initialized SGXquote.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SGXquote NAAAIM_SGXquote_Init(void)

{
	Origin root;

	SGXquote this = NULL;

	struct HurdLib_Origin_Retn retn;

	struct SGXquote_ocall ocall;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SGXquote);
	retn.state_size   = sizeof(struct NAAAIM_SGXquote_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SGXquote_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize the untrusted object. */
	memset(&ocall, '\0', sizeof(struct SGXquote_ocall));
	ocall.ocall = SGXquote_init_object;
	if ( sgxquote_ocall(&ocall) != 0 )
		goto err;
	this->state->instance = ocall.instance;

	/* Method initialization. */
	this->init = init;

	this->generate_quote  = generate_quote;
	this->generate_report = generate_report;

	this->get_qe_targetinfo = get_qe_targetinfo;

	this->whack = whack;

	return this;


 err:
	root->whack(root, this, this->state);
	return NULL;
}
