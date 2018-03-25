/** \file
 * This file contains the implementation of an object which is used to
 * manage the creation and verification of an enclave quote.
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
#include "Base64.h"
#include "HTTP.h"
#include "SGX.h"
#include "QEenclave.h"
#include "PCEenclave.h"
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

	/* Object status. */
	_Bool poisoned;

	/* The PCE platform security version. */
	struct SGX_psvn pce_psvn;

	/* Quoting enclave target information. */
	struct SGX_targetinfo qe_target_info;

	/* The quoting enclave. */
	QEenclave qe;

	/* The object containing the quote. */
	Buffer quote;
};


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

	memset(&S->pce_psvn, '\0', sizeof(struct SGX_psvn));
	memset(&S->qe_target_info, '\0', sizeof(struct SGX_targetinfo));

	S->qe	 = NULL;
	S->quote = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the initialization of the quote object.
 * The initialization process consists of the following steps:
 *
 *	- Obtain quoting enclave target information.
 *
 *	- Request load of EPID blob into quoting enclave.
 *
 *	- Obtain PCE enclave security version.
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

	PCEenclave pce = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Initialize the quoting enclave. */
	INIT(NAAAIM, QEenclave, S->qe, ERR(goto done));
	if ( !S->qe->open(S->qe, quote_token) )
		ERR(goto done);

	S->qe->get_target_info(S->qe, &S->qe_target_info);

	if ( !S->qe->load_epid(S->qe, epid_blob) )
		ERR(goto done);


	/*
	 * Initialize the PCE enclave and abstract the platform
	 * security information.
	 */
	INIT(NAAAIM, PCEenclave, pce, ERR(goto done));
	if ( !pce->open(pce, pce_token) )
		ERR(goto done);

	pce->get_psvn(pce, &S->pce_psvn);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(pce);

	return retn;
}


/**
 * External public method.
 *
 * This method implements the generation of an enclave quote for
 * remote attestation.
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


	/* Generate quote into object specific buffer. */
	INIT(HurdLib, Buffer, S->quote, ERR(goto done));
	if ( !S->qe->generate_quote(S->qe, report, 0, spid, nonce, NULL, \
				    quote, S->pce_psvn.isv_svn) )
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
 * This method implements the generation of an enclave quote for
 * remote attestation.
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

static _Bool generate_report(CO(SGXquote, this), CO(Buffer, quote), \
			     CO(String, report))

{
	STATE(S);

	_Bool retn = false;

	char *url = "https://as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/report";

	Buffer http_in	= NULL,
	       http_out = NULL;

	Base64 base64 = NULL;

	HTTP http = NULL;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( quote->poisoned(quote) )
		ERR(goto done);


	/* Encode the quote for transmission. */
	INIT(NAAAIM, Base64, base64, ERR(goto done));

	if ( !report->add(report, "{\r\n\"isvEnclaveQuote\":\"") )
		ERR(goto done)
	if ( !base64->encode(base64, quote, report) )
		ERR(goto done);
	if ( !report->add(report, "\"\r\n}\r\n") )
		ERR(goto done);


	/* Post the encoded quote to the IAS servers. */
	INIT(HurdLib, Buffer, http_in, ERR(goto done));
	INIT(HurdLib, Buffer, http_out, ERR(goto done));
	INIT(NAAAIM, HTTP, http, ERR(goto done));

	http->add_arg(http, "-v");
	http->add_arg(http, "-S");
	http->add_arg(http, "--no-check-certificate");
	http->add_arg(http, "--secure-protocol=TLSv1_2");
	http->add_arg(http, "--private-key=ias-key.pem");
	http->add_arg(http, "--certificate=ias-cert.pem");
	http->add_arg(http, "-oias.log");

	if ( !http_in->add(http_in, (unsigned char *) report->get(report), \
			   report->size(report)) )
		ERR(goto done);
	if ( !http->post(http, url, http_in, http_out) )
		ERR(goto done);
	if ( !http_out->add(http_out, (unsigned char *) "\0", 1) )
		ERR(goto done);

	report->reset(report);
	if ( !report->add(report, (char *) http_out->get(http_out)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(http_in);
	WHACK(http_out);
	WHACK(base64);
	WHACK(http)

	return true;
}


/**
 * External public method.
 *
 * This method implements an accessor method for returning a pointer
 * to the structure containing target information for the quoting
 * enclave.
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

	return &S->qe_target_info;
}


/**
 * External public method.
 *
 * This method implements a destructor for the SGXquote object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SGXquote, this))

{
	STATE(S);

	WHACK(S->qe);
	WHACK(S->quote);

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

	/* Method initialization. */
	this->init = init;

	this->generate_quote  = generate_quote;
	this->generate_report = generate_report;

	this->get_qe_targetinfo = get_qe_targetinfo;

	this->whack = whack;

	return this;
}
