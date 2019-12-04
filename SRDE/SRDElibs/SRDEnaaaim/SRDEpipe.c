/** \file
 * This file implements methods which encapsulate the OCALL's needed
 * to implement SRDEpipe based communications with another enclave on
 * the same host.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <SRDE.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "NAAAIM.h"
#include "Curve25519.h"
#include "Report.h"
#include "SRDEpipe.h"


/* State extraction macro. */
#define STATE(var) CO(SRDEpipe_State, var) = this->state



/*
 * The Intel SDK version of this function is being used until the
 * loader initialization issue is addressed.
 */
#if 0
static _Bool SGXidf_trusted_region(void *ptr, size_t size)

{
	_Bool retn = false;

	if ( ptr == NULL )
		goto done;
	if ( sgx_is_outside_enclave(ptr, size) )
		goto done;
	retn = true;
 done:
	return retn;
}
#endif


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEpipe_OBJID)
#error Object identifier not defined.
#endif


/** SRDEpipe private state information. */
struct NAAAIM_SRDEpipe_State
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

	/* Connect status. */
	enum {
		SRDEpipe_state_init,
		SRDEpipe_state_wait,
		SRDEpipe_state_connected
	} state;

	/* Elliptic curve object. */
	Curve25519 dhkey;

	/* Initialization vector. */
	Buffer iv;

	/* Shared key. */
	Buffer key;
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

static int SRDEpipe_ocall(struct SRDEpipe_ocall *ocall)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	size_t arena_size = sizeof(struct SRDEpipe_ocall);

	struct SRDEpipe_ocall *ocp = NULL;


	/* Verify arguements and set size of arena. */

	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena and pointers to it. */
#if 0
	if ( ocall->ocall == Duct_send_buffer ) {
		memcpy(ocp->arena, ocall->bufr, ocall->size);
		ocp->bufr = ocp->arena;
	}
#endif


	/* Call the SRDEpipe manager. */
	if ( (status = sgx_ocall(SRDENAAAIM_OCALL4, ocp)) == 0 ) {
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
 * This method is responsible for initializing the NAAAIM_SRDEpipe_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S	A pointer to the object containing the state
 *		information that is to be initialized.
 */

static void _init_state(CO(SRDEpipe_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Duct_OBJID;


	S->poisoned = false;
	S->state    = SRDEpipe_state_init;

	S->dhkey = NULL;

	S->iv  = NULL;
	S->key = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the initialization and setup of the enclave
 * that will be communicated with.
 *
 * \param this		A pointer to the object which is to have an
 *			enclave associated with it.
 *
 * \param name		A pointer to a null terminated buffer containing
 *			the pathname of the enclave to open.
 *
 * \param slot		The slot number of the enclave that will implement
 *			the pipe endpoint.
 *
 * \param token		A pointer to a null terminated buffer containing
 *			the pathname of the launch token to be used
 *			for initializing the enclave.
 *
 * \param debug		A flag to indicate whether or not the enclave
 *			is to be initialized in debug or production mode.
 *
 * \return		A false value is returned if an error is
 *			encountered while setting the enclave up.  The
 *			object is poisoned and is not available for
 *			additional processing.  If the setup was successful
 *			a true value is returned to the caller.
 */

static _Bool setup(CO(SRDEpipe, this), CO(char *, name), const int slot, \
		   CO(char *, token), const _Bool debug)

{
	STATE(S);

	_Bool retn = false;

	struct SRDEpipe_ocall ocall;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));

	ocall.debug = debug;
	ocall.slot  = slot;

	if ( (strlen(name) + 1) > sizeof(ocall.enclave) )
		ERR(goto done);
	memcpy(ocall.enclave, name, strlen(name));

	if ( (strlen(token) + 1) > sizeof(ocall.token) )
		ERR(goto done);
	memcpy(ocall.token, token, strlen(token));

	ocall.ocall    = SRDEpipe_setup;
	ocall.instance = S->instance;
	if ( SRDEpipe_ocall(&ocall) != 0 )
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
 * This method is an API placeholder for the method that is implemented
 * in standard userspace to issue the ECALL's needed to setup the
 * security context between two enclaves that are to implement a
 * communications conduit.
 *
 * \param this		A pointer to the object which is to implement
 *			the connection.
 *
 * \param target	A pointer to the structure containing target
 *			information that an attestation report is to
 *			be generated against.
 *
 * \param report	A pointer to the structuring containing a local
 *			attestation report.
 *
 * \return		A false value is universally returned in order
 *			to prevent this method from being invoked from
 *			enclave context.
 */

static _Bool bind(CO(SRDEpipe, this), struct SGX_targetinfo *target, \
		  struct SGX_report *report)

{
	return false;
}


/**
 * External public method.
 *
 * This method drives the creation of a security context with another
 * enclave that has been previously created and initialized with the
 * ->setup method.
 *
 * \param this	A pointer to the object which is to implement the
 *		connection.
 *
 * \return	A boolean value is returned to indication the status
 *		of the connection setup.  A false value indicates the
 *		establishment of the communications context has been
 *		failed and the object is poisoned from subsequent use.
 *		A true value indicates that a communications context
 *		has been established between the two enclaves.
 */

static _Bool connect(CO(SRDEpipe, this))

{
	STATE(S);

	_Bool status,
	      retn = false;

	struct SRDEpipe_ocall ocall;

	Buffer bufr = NULL;

	Report rpt = NULL;


	/* Setup OCALL structure. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));

	ocall.ocall    = SRDEpipe_connect;
	ocall.instance = S->instance;


	/* Generate target information for remote endpoint. */
	INIT(NAAAIM, Report, rpt, ERR(goto done));
	if ( !rpt->get_targetinfo(rpt, &ocall.target) )
		ERR(goto done);


	/* Invoke OCALL to get report from remote endpoint. */
	if ( SRDEpipe_ocall(&ocall) != 0 )
		ERR(goto done);


	/* Validate remote report and generate report for endpoint. */
	if ( !rpt->validate_report(rpt, &ocall.report, &status) )
		ERR(goto done);
	if ( !status )
		ERR(goto done);

	fputs("Validated target endpoint.\n", stdout);


	/* Generate shared key and counter-report. */
	INIT(NAAAIM, Curve25519, S->dhkey, ERR(goto done));
	if ( !S->dhkey->generate(S->dhkey) )
		ERR(goto done);

	INIT(HurdLib, Buffer, S->key, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !bufr->add(bufr, ocall.report.body.reportdata, 32) )
		ERR(goto done);
	if ( !S->dhkey->compute(S->dhkey, bufr, S->key) )
		ERR(goto done);

	fputs("\nShared key:\n", stdout);
	S->key->print(S->key);

	if ( !rpt->generate_report(rpt, &ocall.target,		   \
				   S->dhkey->get_public(S->dhkey), \
				   &ocall.report) )
			ERR(goto done);


	/* Invoke OCALL to get report from remote endpoint. */
	if ( SRDEpipe_ocall(&ocall) != 0 )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);
	WHACK(rpt);

	return retn;
}


/**
 * External public method.
 *
 * This method handles the client side of creating a security context
 * from an enclave that is invoking the ->connect method.
 *
 * \param this		A pointer to the object which is to implement
 *			acceptance of a connection.
 *
 * \param target	A pointer to a target structure that contains
 *			a target that a report is to be generated
 *			against.  This structure will be populated
 *			with a report for the executing enclave upon
 *			initial connection acceptance.
 *
 * \param report	A pointer to a report structure that will
 *			be populated with a report of the executing
 *			enclave or alternately the report from the
 *			enclave initiating the connection.
 *
 * \return	A boolean value is returned to indication the status
 *		of the connection setup.  A false value indicates the
 *		establishment of the communications context has failed
 *		and the object is poisoned from subsequent use. A true
 *		value indicates that a communications context has been
 *		established between the two enclaves.
 */

static _Bool accept(CO(SRDEpipe, this), struct SGX_targetinfo *target, \
		    struct SGX_report *report)

{
	STATE(S);

	_Bool status,
	      retn = false;

	Buffer bufr = NULL;

	Report rpt = NULL;


	INIT(NAAAIM, Report, rpt, ERR(goto done));

	/* Initial endpoint. */
	if ( S->dhkey == NULL ) {
		INIT(NAAAIM, Curve25519, S->dhkey, ERR(goto done));
		if ( !S->dhkey->generate(S->dhkey) )
			ERR(goto done);

		if ( !rpt->generate_report(rpt, target,			   \
					   S->dhkey->get_public(S->dhkey), \
					   report) )
			ERR(goto done);
		if ( !rpt->get_targetinfo(rpt, target) )
			ERR(goto done);

		retn	 = true;
		S->state = SRDEpipe_state_wait;
		goto done;
	}


	/* Validate counter party report. */
	if ( S->state != SRDEpipe_state_wait )
		ERR(goto done);

	if ( !rpt->validate_report(rpt, report, &status) )
		ERR(goto done);

	if ( status )
		fputs("\nSource report verified.\n", stdout);
	else {
		fputs("\nSource report not verified.\n", stdout);
		ERR(goto done);
	}


	/* Generate the shared key. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, report->body.reportdata, 32) )
		ERR(goto done);

	INIT(HurdLib, Buffer, S->key, ERR(goto done));
	if ( !S->dhkey->compute(S->dhkey, bufr, S->key) )
		ERR(goto done);

	fputs("\nShared key:\n", stdout);
	S->key->print(S->key);

	S->state = SRDEpipe_state_connected;
	retn     = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(rpt);
	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method returns the current connection state of the pipe.  It
 * is designed to provide a method for the remote endpoint to determine
 * if a second ->accept call is to be made to complete the connection.
 *
 * \param this	A pointer to the object whose connection state is to
 *		be interrogated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the object is connected and has a valid security context.
 *		A false value indicates the object is not connected while
 *		a true value means a security context has been established
 *		and the pipe is available for communications.
 */

static _Bool connected(CO(SRDEpipe, this))

{
	STATE(S);


	if ( S->state == SRDEpipe_state_connected )
		return true;
	else
		return false;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Duct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEpipe, this))

{
	STATE(S);

	struct SRDEpipe_ocall ocall;


	/* Release implementation object. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));
	ocall.ocall    = SRDEpipe_whack;
	ocall.instance = S->instance;
	SRDEpipe_ocall(&ocall);


	/* Destroy resources. */
	WHACK(S->dhkey);

	WHACK(S->iv);
	WHACK(S->key);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEpipe object.
 *
 * \return	A pointer to the initialized SRDEpipe.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEpipe NAAAIM_SRDEpipe_Init(void)

{
	Origin root;

	SRDEpipe this = NULL;

	struct HurdLib_Origin_Retn retn;

	struct SRDEpipe_ocall ocall;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEpipe);
	retn.state_size   = sizeof(struct NAAAIM_SRDEpipe_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Duct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize the untrusted object. */
	memset(&ocall, '\0', sizeof(struct SRDEpipe_ocall));
	ocall.ocall = SRDEpipe_init_object;
	if ( SRDEpipe_ocall(&ocall) != 0 )
		goto err;
	this->state->instance = ocall.instance;

	/* Method initialization. */
	this->setup = setup;
	this->bind    = bind;

	this->connect = connect;
	this->accept  = accept;

	this->connected = connected;
	this->whack	= whack;

	return this;


 err:
	root->whack(root, this, this->state);
	return NULL;
}
