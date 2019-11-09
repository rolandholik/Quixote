/** \file
 * This file contains the implementation of an enclave based object
 * used to prompt a user for a passphrase.  It provides an object API
 * consistent with the standard userspace object.  The actual
 * implementation of passphrase soliciation is done by executing an
 * OCALL that instantiates a Prompt object.  The passphrase solicited
 * by the object is returned to the caller in the interface structure.
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
#include <string.h>

#include <openssl/ui.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "NAAAIM.h"
#include "Prompt.h"


/* State definition macro. */
#define STATE(var) CO(Prompt_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Prompt_OBJID)
#error Object identifier not defined.
#endif


/** Prompt private state information. */
struct NAAAIM_Prompt_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Prompt_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(Prompt_State, S))

{

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Prompt_OBJID;

	S->poisoned = false;

	return;
}


/**
 * External public method.
 *
 * This method implements the request for a passphrase.
 *
 * \param this	A pointer to the object which is requesting the
 *		generation of a passphrase.
 *
 * \param prompt	The object containing the prompt that is to
 *			be displayed.
 *
 * \param verify	The object containing the verification prompt
 *			that is to be displayed.  Specifying a NULL
 *			value causes verification not to be requested.
 *
 * \param maximum	The maximum size of the phrase not including
 *			the terminal NULL.
 *
 * \param phrase	The object that will be loaded with the
 *			entered passphase.
 *
 * \param pwdfail	A pointer to a boolean value that will be set
 *			to the status of the passphrase prompting
 *			process.  This value may be set to true if
 *			the maximum buffer capacity is exceeded or
 *			if password verfication fails.
 *
 * \return		A boolean value is used to indicate the status
 *			of passphrase acquisition.  A false value
 *			indicates an error was encountered and the
 *			output object is in an indeterminate state.  A
 *			true value indicates the passphrase was
 *			successfully entered and the object can be
 *			assumed to contain a valid passphrase.
 */

static _Bool get(CO(Prompt, this), CO(String, prompt), CO(String, verify), \
		 const int maximum, CO(String, phrase), _Bool *pwdfail)

{
	STATE(S);

	_Bool retn = false;

	size_t arena_size = sizeof(struct SRDEnaaaim_ocall3_interface);

	struct SRDEnaaaim_ocall3_interface *ocp = NULL;


	/* Verify object status and arguements. */
	if ( S->poisoned )
		ERR(goto done);
	if ( prompt == NULL )
		ERR(goto done);
	if ( prompt->poisoned(prompt) )
		ERR(goto done);
	if ( prompt->size(prompt) > (sizeof(ocp->prompt) - 1) )
		ERR(goto done);

	if ( maximum > (sizeof(ocp->prompt) - 1) )
		ERR(goto done);
	if ( maximum > (sizeof(ocp->vprompt) - 1) )
		ERR(goto done);

	if ( verify != NULL ) {
		if ( verify->size(verify) > (sizeof(ocp->vprompt) - 1) )
			ERR(goto done);
	}


	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	ocp->maximum = maximum;

	memcpy(ocp->prompt, prompt->get(prompt), prompt->size(prompt));
	if ( verify != NULL ) {
		ocp->verify = true;
		memcpy(ocp->vprompt, verify->get(verify), \
		       verify->size(verify));
	}


	/* Call the standard userspace Prompt implementation. */
	if ( sgx_ocall(SRDENAAAIM_OCALL3, ocp) != 0 )
		ERR(goto done);

	if ( !ocp->retn )
		ERR(goto done);
	if ( !phrase->add(phrase, ocp->pwd) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	memset(ocp, '\0', arena_size);
	sgx_ocfree();

	return retn;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Prompt object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Prompt, this))

{
	STATE(S);


	S->root->whack(S->root, this, S);
	return;
}

/**
 * External constructor call.
 *
 * This function implements a constructor call for a Prompt object.
 *
 * \return	A pointer to the initialized Prompt.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Prompt NAAAIM_Prompt_Init(void)

{
	Origin root;

	Prompt this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Prompt);
	retn.state_size   = sizeof(struct NAAAIM_Prompt_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Prompt_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->get = get;

	this->whack = whack;

	return this;
}
