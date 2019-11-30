/** \file
 * This file implements an SRDEpipe manager which manages
 * implementation objects on behalf of an SRDEpipe object running in
 * enclave context.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SRDEpipe.h"


/** Duct objects under external management. */
static _Bool SRDE_pipe_initialized = false;

static SRDEpipe SRDE_pipes[16];


/**
 * Internal private function.
 *
 * This function manages the initialization of a SRDEpipe object to
 * implement functionality for an enclave based SRDEpipe object.  The
 * object instance slot is returned and stored in the enclave based object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void srdepipe_init_object(struct SRDEpipe_ocall *ocp)

{
	_Bool retn = false;

	unsigned int instance;

	SRDEpipe pipe = NULL;


	for (instance= 0; instance < sizeof(SRDE_pipes)/sizeof(SRDEpipe); \
		     ++instance) {
		if ( SRDE_pipes[instance] == NULL )
			break;
	}
	if ( instance == sizeof(SRDE_pipes)/sizeof(SRDEpipe) )
		ERR(goto done);

	INIT(NAAAIM, SRDEpipe, pipe, ERR(goto done));
	ocp->instance	     = instance;
	SRDE_pipes[instance] = pipe;

	retn = true;


 done:
	if ( !retn ) {
		if ( (pipe = SRDE_pipes[instance]) != NULL ) {
			WHACK(pipe);
			SRDE_pipes[instance] = NULL;
		}
	}
	ocp->retn = retn;

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

static void srdepipe_whack(struct SRDEpipe_ocall *ocp)

{
	SRDEpipe pipe = SRDE_pipes[ocp->instance];

	pipe->whack(pipe);

	SRDE_pipes[ocp->instance] = NULL;

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

int SRDEpipe_mgr(struct SRDEpipe_ocall *ocp)

{
	int rc = -1;


	/* Verify on first call that object array is initialized. */
	if ( !SRDE_pipe_initialized ) {
		memset(SRDE_pipes, '\0', sizeof(SRDE_pipes));
		SRDE_pipe_initialized = true;
	}


	/* Verify ocall method type and instance specification. */
	if ( (ocp->ocall < 0) || (ocp->ocall >= SRDEpipe_END) )
		ERR(goto done);
	if ( ocp->instance >= sizeof(SRDE_pipes)/sizeof(SRDEpipe) )
		ERR(goto done);


	/* Vector execution to the appropriate method handler. */
	switch ( ocp->ocall ) {
		case SRDEpipe_init_object:
			srdepipe_init_object(ocp);
			break;


		case SRDEpipe_whack:
			srdepipe_whack(ocp);
			break;

		case SRDEpipe_END:
			break;
	}
	rc = 0;


 done:
	return rc;
}
