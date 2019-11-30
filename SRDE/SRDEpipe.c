/** \file
 * This file contains the implementation of an object used to
 * local enclave<->enclave communications.  Its primary role is to
 * be an object that is used be the SRDEpipe_mgr in order to
 * communication state between two enclaves in standard userspace.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <Origin.h>
#include <HurdLib.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SRDEenclave.h"
#include "SRDEpipe.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEpipe_State, var) = this->state


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

	/* Object status. */
	_Bool poisoned;

	/* ECALL slot number to communicate with. */
	int slot;

	/* Enclave to be managed. */
	SRDEenclave enclave;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEpipe_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state
 *		information which is to be initialized.
 */

static void _init_state(const SRDEpipe_State const S)

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEpipe_OBJID;

	S->poisoned = false;

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
 *			encountered in setting up the enclave.  A true
 *			value is returned to indicate that the enclave
 *			setup was successful and available for use.
 */

static _Bool setup(CO(SRDEpipe, this), CO(char *, name), const int slot, \
		   CO(char *, token), const _Bool debug)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Set the slot number and initialize the enclave. */
	S->slot = slot;

	INIT(NAAAIM, SRDEenclave, S->enclave, ERR(goto done));
	if ( !S->enclave->setup(S->enclave, name, token, debug) )
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
 * This method implements a destructor for an SRDEpipe object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEpipe, this))

{
	STATE(S);


	WHACK(S->enclave);

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


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEpipe);
	retn.state_size   = sizeof(struct NAAAIM_SRDEpipe_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEpipe_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->setup = setup;

	this->whack = whack;

	return this;
}
