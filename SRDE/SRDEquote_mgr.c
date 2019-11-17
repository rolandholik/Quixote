/** \file
 * This file implements an SRDEquote manager which manages
 * implementation objects on behalf of an SRDEquote object running in
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
#include "SRDEquote.h"


/** Duct objects under external management. */
static _Bool SRDE_quote_initialized = false;

static Buffer SRDEquote_buffers[16];

static SRDEquote SRDE_quotes[16];


/**
 * Internal private function.
 *
 * This function manages the initialization of a SRDEquote object to
 * implement functionality for an enclave based SRDEquote object.  The
 * object instance slot is returned and stored in the enclave based object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdequote_init_object(struct SRDEquote_ocall *ocp)

{
	_Bool retn = false;

	unsigned int instance;

	Buffer bufr = NULL;

	SRDEquote quote = NULL;


	for (instance= 0; instance < sizeof(SRDE_quotes)/sizeof(SRDEquote); \
		     ++instance) {
		if ( SRDE_quotes[instance] == NULL )
			break;
	}
	if ( instance == sizeof(SRDE_quotes)/sizeof(SRDEquote) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, SRDEquote, quote, ERR(goto done));
	ocp->instance		    = instance;
	SRDE_quotes[instance]	    = quote;
	SRDEquote_buffers[instance] = bufr;

	retn = true;


 done:
	if ( !retn ) {
		if ( (quote = SRDE_quotes[instance]) != NULL ) {
			WHACK(quote);
			SRDE_quotes[instance] = NULL;
		}
	}
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->init method for the enclave
 * Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdequote_init(struct SRDEquote_ocall *ocp)

{
	SRDEquote quote = SRDE_quotes[ocp->instance];


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

static void srdequote_generate_quote(struct SRDEquote_ocall *ocp)

{
	_Bool retn = false;

	Buffer spid	  = NULL,
	       nonce	  = NULL,
	       quote_bufr = SRDEquote_buffers[ocp->instance];

	SRDEquote quote = SRDE_quotes[ocp->instance];


	/* Setup local objects. */
	INIT(HurdLib, Buffer, nonce, ERR(goto done));
	if ( !nonce->add(nonce, ocp->nonce, sizeof(ocp->nonce)) )
		ERR(goto done);

	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add(spid, ocp->spid, sizeof(ocp->spid)) )
		ERR(goto done);


	/* Generate the quote. */
	if ( ocp->development )
		quote->development(quote, true);

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

static void srdequote_generate_report(struct SRDEquote_ocall *ocp)

{
	_Bool retn = false;

	Buffer quote = NULL,
	       report_bufr = SRDEquote_buffers[ocp->instance];

	String apikey = NULL,
	       output = NULL;

	SRDEquote quoter = SRDE_quotes[ocp->instance];


	/* Generate the report. */
	report_bufr->reset(report_bufr);

	if ( ocp->apikey ) {
		INIT(HurdLib, String, apikey, ERR(goto done));
		if ( ocp->key[32] != '\0' )
			ERR(goto done);
		if ( !apikey->add(apikey, (char *) ocp->key) )
			ERR(goto done);
	}

	INIT(HurdLib, Buffer, quote, ERR(goto done));
	if ( !quote->add(quote, ocp->arena, ocp->bufr_size) )
		ERR(goto done);

	INIT(HurdLib, String, output, ERR(goto done));
	if ( !quoter->generate_report(quoter, quote, output, apikey) )
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
	WHACK(apikey);
	WHACK(output);

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->qe_get targetinfo for the enclave
 * based SRDEquote object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdequote_get_qe_targetinfo(struct SRDEquote_ocall *ocp)

{
	SRDEquote quote = SRDE_quotes[ocp->instance];


	ocp->qe_target_info = quote->get_qe_targetinfo(quote);
	ocp->retn = true;

	return;
}


/**
 * Internal private function.
 *
 * This function manages the destruction of an SRDEquote object which
 * has been previously initialized.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdequote_whack(struct SRDEquote_ocall *ocp)

{
	SRDEquote quote = SRDE_quotes[ocp->instance];

	Buffer bufr = SRDEquote_buffers[ocp->instance];


	quote->whack(quote);
	bufr->whack(bufr);

	SRDE_quotes[ocp->instance]	 = NULL;
	SRDEquote_buffers[ocp->instance] = NULL;

	return;
}


/**
 * External function.
 *
 * This function is the external entry point for the enclave OCALL handler.
 *
 * \param ocp	A pointer to the structure which is used to marshall
 *		the data being submitted to and returned from the
 *		enclave OCALL handler.
 *
 * \return	If an error is encountered a non-zero value is
 *		returned to the caller.  Successful processing of
 *		the command returns a value of zero.
 */

int SRDEquote_mgr(struct SRDEquote_ocall *ocp)

{
	int rc = -1;


	/* Verify on first call that object array is initialized. */
	if ( !SRDE_quote_initialized ) {
		memset(SRDE_quotes, '\0', sizeof(SRDE_quotes));
		memset(SRDEquote_buffers, '\0', sizeof(SRDEquote_buffers));
		SRDE_quote_initialized = true;
	}


	/* Verify ocall method type and instance specification. */
	if ( (ocp->ocall < 0) || (ocp->ocall >= SRDEquote_END) )
		ERR(goto done);
	if ( ocp->instance >= sizeof(SRDE_quotes)/sizeof(SRDEquote) )
		ERR(goto done);


	/* Vector execution to the appropriate method handler. */
	switch ( ocp->ocall ) {
		case SRDEquote_init_object:
			srdequote_init_object(ocp);
			break;

		case SRDEquote_init:
			srdequote_init(ocp);
			break;
		case SRDEquote_generate_quote:
			srdequote_generate_quote(ocp);
			break;
		case SRDEquote_generate_report:
			srdequote_generate_report(ocp);
			break;

		case SRDEquote_get_qe_targetinfo:
			srdequote_get_qe_targetinfo(ocp);
			break;

		case SRDEquote_whack:
			srdequote_whack(ocp);
			break;

		case SRDEquote_END:
			break;
	}
	rc = 0;


 done:
	return rc;
}
