/** \file
 * This file implements an SGXquote manager which manages
 * implementation objects on behalf of an SGXquote object running in
 * enclave context.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SGXquote.h"


/** Duct objects under external management. */
static _Bool SGX_SGXquote_initialized = false;

static Buffer SGXquote_Buffers[16];

static SGXquote SGX_SGXquotes[16];


/**
 * Internal private function.
 *
 * This function manages the initialization of a SGXquote object to
 * implement functionality for an enclave based SGXquote object.  The
 * object instance slot is returned and stored in the SGX based object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void sgxquote_init_object(struct SGXquote_ocall *ocp)

{
	_Bool retn = false;

	unsigned int instance;

	Buffer bufr = NULL;

	SGXquote quote = NULL;


	for (instance= 0; instance < sizeof(SGX_SGXquotes)/sizeof(SGXquote); \
		     ++instance) {
		if ( SGX_SGXquotes[instance] == NULL )
			break;
	}
	if ( instance == sizeof(SGX_SGXquotes)/sizeof(SGXquote) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, SGXquote, quote, ERR(goto done));
	ocp->instance		   = instance;
	SGX_SGXquotes[instance]	   = quote;
	SGXquote_Buffers[instance] = bufr;

	retn = true;


 done:
	if ( !retn ) {
		if ( (quote = SGX_SGXquotes[instance]) != NULL ) {
			WHACK(quote);
			SGX_SGXquotes[instance] = NULL;
		}
	}
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->init method for the SGX
 * Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void sgxquote_init(struct SGXquote_ocall *ocp)

{
	SGXquote quote = SGX_SGXquotes[ocp->instance];


	ocp->retn = quote->init(quote, ocp->quote_token, ocp->pce_token, \
				ocp->epid_blob);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->generate_quote method for an enclave
 * based instance of an object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void sgxquote_generate_quote(struct SGXquote_ocall *ocp)

{
	_Bool retn = false;

	Buffer spid	  = NULL,
	       nonce	  = NULL,
	       quote_bufr = SGXquote_Buffers[ocp->instance];

	SGXquote quote = SGX_SGXquotes[ocp->instance];


	/* Setup local objects. */
	INIT(HurdLib, Buffer, nonce, ERR(goto done));
	if ( !nonce->add(nonce, ocp->nonce, sizeof(ocp->nonce)) )
		ERR(goto done);

	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add(spid, ocp->spid, sizeof(ocp->spid)) )
		ERR(goto done);


	/* Generate the quote. */
	quote_bufr->reset(quote_bufr);
	if ( !quote->generate_quote(quote, &ocp->report, spid, nonce, \
				    quote_bufr) )
		ERR(goto done);

	ocp->bufr      = quote_bufr->get(quote_bufr);
	ocp->bufr_size = quote_bufr->size(quote_bufr);
	retn = true;


 done:
	ocp->retn = retn;

	WHACK(spid);
	WHACK(nonce);

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->generate_report method for an enclave
 * based instance of quoting object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void sgxquote_generate_report(struct SGXquote_ocall *ocp)

{
	_Bool retn = false;

	Buffer quote = NULL,
	       report_bufr = SGXquote_Buffers[ocp->instance];

	String output = NULL;

	SGXquote quoter = SGX_SGXquotes[ocp->instance];


	/* Generate the report. */
	report_bufr->reset(report_bufr);

	INIT(HurdLib, Buffer, quote, ERR(goto done));
	if ( !quote->add(quote, ocp->arena, ocp->bufr_size) )
		ERR(goto done);

	INIT(HurdLib, String, output, ERR(goto done));
	if ( !quoter->generate_report(quoter, quote, output) )
		ERR(goto done);

	if ( !report_bufr->add(report_bufr, (void *) output->get(output), \
			       output->size(output) + 1) )
		ERR(goto done);

	ocp->bufr      = report_bufr->get(report_bufr);
	ocp->bufr_size = report_bufr->size(report_bufr);
	retn = true;


 done:
	ocp->retn = retn;

	WHACK(quote);
	WHACK(output);

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->qe_get targetinfo for the enclave
 * based SGXquote object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void sgxquote_get_qe_targetinfo(struct SGXquote_ocall *ocp)

{
	SGXquote quote = SGX_SGXquotes[ocp->instance];


	ocp->qe_target_info = quote->get_qe_targetinfo(quote);
	ocp->retn = true;

	return;
}


/**
 * Internal private function.
 *
 * This function manages the destruction of an SGXquote object which
 * has been previously initialized.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void sgxquote_whack(struct SGXquote_ocall *ocp)

{
	SGXquote quote = SGX_SGXquotes[ocp->instance];

	Buffer bufr = SGXquote_Buffers[ocp->instance];


	quote->whack(quote);
	bufr->whack(bufr);

	SGX_SGXquotes[ocp->instance]	 = NULL;
	SGXquote_Buffers[ocp->instance] = NULL;

	return;
}


/**
 * External function.
 *
 * This function is the external entry point for the SGX OCALL handler.
 *
 * \param ocp	A pointer to the structure which is used to marshall
 *		the data being submitted to and returned from the
 *		SGX OCALL handler.
 *
 * \return	If an error is encountered a non-zero value is
 *		returned to the caller.  Successful processing of
 *		the command returns a value of zero.
 */

int SGXquote_sgxmgr(struct SGXquote_ocall *ocp)

{
	int rc = -1;


	/* Verify on first call that object array is initialized. */
	if ( !SGX_SGXquote_initialized ) {
		memset(SGX_SGXquotes, '\0', sizeof(SGX_SGXquotes));
		memset(SGXquote_Buffers, '\0', sizeof(SGXquote_Buffers));
		SGX_SGXquote_initialized = true;
	}


	/* Verify ocall method type and instance specification. */
	if ( (ocp->ocall < 0) || (ocp->ocall >= SGXquote_END) )
		ERR(goto done);
	if ( ocp->instance >= sizeof(SGX_SGXquotes)/sizeof(SGXquote) )
		ERR(goto done);


	/* Vector execution to the appropriate method handler. */
	switch ( ocp->ocall ) {
		case SGXquote_init_object:
			sgxquote_init_object(ocp);
			break;

		case SGXquote_init:
			sgxquote_init(ocp);
			break;
		case SGXquote_generate_quote:
			sgxquote_generate_quote(ocp);
			break;
		case SGXquote_generate_report:
			sgxquote_generate_report(ocp);
			break;

		case SGXquote_get_qe_targetinfo:
			sgxquote_get_qe_targetinfo(ocp);
			break;

		case SGXquote_whack:
			sgxquote_whack(ocp);
			break;

		case SGXquote_END:
			break;
	}
	rc = 0;


 done:
	return rc;
}
