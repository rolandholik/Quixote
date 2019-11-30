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

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "NAAAIM.h"
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


	S->poisoned	= false;

	return;
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
	fputs("Initializing SRDEpipe.\n", stdout);
	if ( SRDEpipe_ocall(&ocall) != 0 ) {
		fputs("Failed OCALL: %d\n", stdout);
		goto err;
	}
	this->state->instance = ocall.instance;

	/* Method initialization. */
	this->whack		= whack;

	return this;


 err:
	root->whack(root, this, this->state);
	return NULL;
}
