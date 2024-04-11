/** \file
 * This file contains the implementation of an object which manages
 * an security interaction event in a Turing Security Event Model.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <Gaggle.h>

#include "NAAAIM.h"
#include "SecurityEvent.h"
#include "EventModel.h"

#if !defined(REG_OK)
#define REG_OK REG_NOERROR
#endif


/* Object state extraction macro. */
#define STATE(var) CO(EventModel_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_EventModel_OBJID)
#error Object identifier not defined.
#endif


/** EventModel private state information. */
struct NAAAIM_EventModel_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* List of pseudonyms for the model. */
	Gaggle pseudonyms;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the
 * NAAAIM_ExhangeEvent_State structure which holds state information
 * for the model
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(EventModel_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_EventModel_OBJID;

	S->poisoned = false;

	S->pseudonyms = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the addition of a pseudonym for the defined
 * model.
 *
 * \param this		A pointer to the model that the pseudonym will
 *			be added to.
 *
 * \param pseudonum	The object containing the pseudonym value
 *			to be added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the addition of the pseudonym was successful.  A
 *		true value indicates the pseudonym was successfully
 *		added while a false value indicates an error was
 *		encountered while adding the pseudonym.
 */

static _Bool add_pseudonym(CO(EventModel, this), CO(Buffer, pseudonym))

{
	STATE(S);

	_Bool retn = false;

	Buffer bufr = NULL;


	/* Verify the object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( pseudonym->poisoned(pseudonym) )
		ERR(goto done);


	/* Create the object that will hold the pseudonym. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !bufr->add_Buffer(bufr, pseudonym) )
		ERR(goto done);


	/* Add the pseudonym to the current list. */
	if ( S->pseudonyms == NULL ) {
		INIT(HurdLib, Gaggle, S->pseudonyms, ERR(goto done));
	}

	if ( !GADD(S->pseudonyms, bufr) )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn ) {
		S->poisoned = true;
		WHACK(bufr);
	}

	return retn;
}


/**
 * Internal private function.
 *
 * This private method evaluates the event to determine whether or
 * not it has been registered as a pseudonym.
 *
 *
 * \param pseudonyms	The object containing the list of pseudonyms
 *			to evaluate the event against.
 *
 * \param event		The object defining the event to be
 *			evaluated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		an error was encountered during the event evaluation.
 *		A true value indicates that pseudonym processing
 *		was complete while a value value indicates an error.
 */

static _Bool _evaluate_pseudonyms(CO(Gaggle, pseudonyms), \
				  CO(SecurityEvent, event))

{
	_Bool retn = false;

	size_t cnt = pseudonyms->size(pseudonyms);

	Buffer pseudonym;


	/* No processing to be done. */
	if ( cnt == 0 ) {
		retn = true;
		goto done;
	}


	/* Loop over the list of pseudonyms and evaluate the event. */
	pseudonyms->rewind_cursor(pseudonyms);

	while ( cnt-- ) {
		pseudonym = GGET(pseudonyms, pseudonym);
		if ( !event->evaluate_pseudonym(event, pseudonym) )
			ERR(goto done);
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the evaluation of a security interaction event
 * in the context of a defined model.  The event parameters are updated
 * to represent the final characteristics of the event that will be
 * used to generate the security state point.
 *
 * \param this	A pointer to the object that will be implementing
 *		the evaluation.
 *
 * \param event	The object describing the security interaction
 *		event that will be evaluated.
 *
 * \return	A boolean value is used to indicate whether or not
 *		any errors were encountered during evaluation of the
 *		event.  A true value indicates that the event was
 *		successfully evaluated while a false value indicates
 *		that an error occurred and the security interaction
 *		event must be considered suspect.
 */

static _Bool evaluate(CO(EventModel, this), CO(SecurityEvent, event))

{
	_Bool retn = false;

	STATE(S);


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Evaluate the event for it being a pseudonym. */
	if ( !_evaluate_pseudonyms(S->pseudonyms, event) )
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
 * This method implements a destructor for an EventModel object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(EventModel, this))

{
	STATE(S);


	if ( S->pseudonyms != NULL ) {
		GWHACK(S->pseudonyms, Buffer);
		WHACK(S->pseudonyms);
	}

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for an EventModel object.
 *
 * \return	A pointer to the initialized interaction event.  A null value
 *		indicates an error was encountered in object generation.
 */

extern EventModel NAAAIM_EventModel_Init(void)

{
	Origin root;

	EventModel this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_EventModel);
	retn.state_size   = sizeof(struct NAAAIM_EventModel_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_EventModel_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->add_pseudonym = add_pseudonym;

	this->evaluate = evaluate;

	this->whack = whack;

	return this;
}
