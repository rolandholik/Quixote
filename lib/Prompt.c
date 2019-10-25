/** \file
 * This file contains the implementation of an object used to prompt
 * a user for a passphrase.  The object can optionally request that
 * the passphrase be validated for correctness.
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

#include <openssl/ui.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

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

	String vbufr = NULL;

	UI *ui = NULL;


	/* Verify object and arguement status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( prompt == NULL )
		ERR(goto done);
	if ( prompt->poisoned(prompt) )
		ERR(goto done);
	if ( phrase == NULL )
		ERR(goto done);
	if ( phrase->poisoned(phrase) )
		ERR(goto done);
	if ( phrase->size(phrase) != 0 )
		ERR(goto done);


	/* Set the size of the output object. */
	while ( phrase->size(phrase) < maximum )
		phrase->add(phrase, " ");
	if ( phrase->poisoned(phrase) )
		ERR(goto done);


	/* Create the user interface and prompt for input. */
	if ( (ui = UI_new()) == NULL )
		ERR(goto done);
	if ( UI_add_input_string(ui, prompt->get(prompt), 0, \
				 phrase->get(phrase), 0, maximum) < 0 )
		ERR(goto done);


	/* Add a verify string if requested. */
	if ( verify != NULL ) {
		INIT(HurdLib, String, vbufr, ERR(goto done));
		while ( vbufr->size(vbufr) < maximum )
			vbufr->add(vbufr, " ");
		if ( vbufr->poisoned(vbufr) )
			ERR(goto done);

		if ( UI_add_verify_string(ui, prompt->get(prompt), 0,	   \
					  verify->get(verify), 0, maximum, \
					  phrase->get(phrase)) < 0 )
			ERR(goto done);
	}


	/* Prompt for the passphrase. */
	if ( UI_process(ui) == 0 )
		*pwdfail = false;
	else
		*pwdfail = true;

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(vbufr);
	UI_free(ui);

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
