/** \file
 * This file contains the implementation of an object which manages
 * an information exchange event in the IDfusion iso-identity modeling
 * architecture.  
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "ExchangeEvent.h"
#include "Actor.h"
#include "Subject.h"


/* Object state extraction macro. */
#define STATE(var) CO(ExchangeEvent_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_ExchangeEvent_OBJID)
#error Object identifier not defined.
#endif


/** ExchangeEvent private state information. */
struct NAAAIM_ExchangeEvent_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Actor identity. */
	Actor actor;

	/* Subject identity. */
	Subject subject;

	/* Event identity/measurement. */
	SHA256 identity;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the
 * NAAAIM_ExhangeEvent_State structure which holds state information
 * for each the event.
 *
 * \param S	A pointer to the object containing the state information
 *		which is to be initialized.
 */

static void _init_state(CO(ExchangeEvent_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_ExchangeEvent_OBJID;

	S->poisoned = false;

	S->actor       = NULL;
	S->subject     = NULL;
	S->identity    = NULL;

	return;
}


/**
 * External public method.
 *
 * This method the parsing of an information exchange event in ASCII
 * form.  This method uses the Actor and Subject objects to parse
 * and aggregate those components of the event.
 *
 * \param this	A pointer to the exchange event object which is to
 *	        be parsed.
 *
 * \param event	The object containing the string which is to be
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool parse(CO(ExchangeEvent, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object and event state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);

	/* Parse the components. */
	if ( !S->actor->parse(S->actor, event) )
		ERR(goto done);
	if ( !S->subject->parse(S->subject, event) )
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
 * This method the parsing of an information exchange event in ASCII
 * form.  This method uses the Actor and Subject objects to parse
 * and aggregate those components of the event.
 *
 * \param this	A pointer to the exchange event object which is to
 *	        be parsed.
 *
 * \param event	The object containing the string which is to be
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool measure(CO(ExchangeEvent, this))

{
	STATE(S);

	_Bool retn = false;

	uint32_t length = NAAAIM_IDSIZE;

	Buffer bufr = NULL;


	/* Verify object and event state. */
	if ( S->poisoned )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	/* Measure the individual components. */
	if ( !S->actor->measure(S->actor) )
		ERR(goto done);
	if ( !S->subject->measure(S->subject) )
		ERR(goto done);

	/* Compute the intersection identity/measurement. */
	if ( !bufr->add(bufr, (unsigned char * ) &length, \
			sizeof(length)) )
		ERR(goto done);
	if ( !S->actor->get_measurement(S->actor, bufr) )
		ERR(goto done);

	if ( !bufr->add(bufr, (unsigned char *) &length, \
			sizeof(length)) )
		ERR(goto done);
	if ( !S->subject->get_measurement(S->subject, bufr) )
		ERR(goto done);

	S->identity->add(S->identity, bufr);
	if ( !S->identity->compute(S->identity) )
		ERR(goto done);

	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor function for retrieving the
 * idnetity/measurement of an exchange event.  It is considered to
 * be a terminal error for the object for this function to be called
 * without previously calling the ->measurement method.
 *
 * \param this	A pointer to the actor identity whose identity is
 *		to be retrieved.
 *
 * \param bufr	The object which the identity is to be loaded into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the supplied object has a valid measurement copied into
 *		it.  A false value indicates the object does not have
 *		a valid measurement and that the current object is now
 *		in a poisoned state.  A true value indicates the
 *		supplied object has a valid copy of this object's
 *		measurement.
 */

static _Bool get_identity(CO(ExchangeEvent, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( !S->identity )
		ERR(goto done);

	if ( !bufr->add_Buffer(bufr, S->identity->get_Buffer(S->identity)) )
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
 * This method implements the reset of an information exchange event
 * object to a state which would allow the processing of a new
 * exchange event.
 *
 * \param this	A pointer to the exchange event object which is to
 *	        be reset.
 */

static void reset(CO(ExchangeEvent, this))

{
	STATE(S);

	S->poisoned = false;

	S->actor->reset(S->actor);
	S->subject->reset(S->subject);
	S->identity->reset(S->identity);

	return;
}


/**
 * External public method.
 *
 * This method implements output of the characteristis of the exchange
 * event represented by the object.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump(CO(ExchangeEvent, this))

{
	STATE(S);

	if ( S->poisoned )
		fputs("*Poisoned.\n", stdout);

	fputs("Actor:\n", stdout);
	S->actor->dump(S->actor);

	fputs("\nSubject:\n", stdout);
	S->subject->dump(S->subject);

 	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for an ExchangeEvent object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(ExchangeEvent, this))

{
	STATE(S);

	WHACK(S->actor);
	WHACK(S->subject);
	WHACK(S->identity);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for an ExchangeEvent object.
 *
 * \return	A pointer to the initialized exchange event.  A null value
 *		indicates an error was encountered in object generation.
 */

extern ExchangeEvent NAAAIM_ExchangeEvent_Init(void)

{
	Origin root;

	ExchangeEvent this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_ExchangeEvent);
	retn.state_size   = sizeof(struct NAAAIM_ExchangeEvent_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_ExchangeEvent_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(NAAAIM, Actor, this->state->actor, ERR(goto fail));
	INIT(NAAAIM, Subject, this->state->subject, ERR(goto fail));
	INIT(NAAAIM, SHA256, this->state->identity, ERR(goto fail));

	/* Method initialization. */
	this->parse	   = parse;
	this->measure	   = measure;
	this->get_identity = get_identity;

	this->reset = reset;
	this->dump  = dump;
	this->whack = whack;

	return this;

fail:
	WHACK(this->state->actor);
	WHACK(this->state->subject);

	root->whack(root, this, this->state);
	return NULL;
}
