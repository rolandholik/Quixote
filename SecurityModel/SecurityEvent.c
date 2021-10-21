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
#include <regex.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "SecurityEvent.h"
#include "COE.h"
#include "Cell.h"

#if !defined(REG_OK)
#define REG_OK REG_NOERROR
#endif


/* Object state extraction macro. */
#define STATE(var) CO(SecurityEvent_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SecurityEvent_OBJID)
#error Object identifier not defined.
#endif


/** SecurityEvent private state information. */
struct NAAAIM_SecurityEvent_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* The process id involved in the event. */
	pid_t pid;

	/* Event description .*/
	String event;

	/* COE characteristics. */
	COE coe;

	/* Cell characteristics. */
	Cell cell;

	/* Event identity/measurement. */
	Sha256 identity;
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

static void _init_state(CO(SecurityEvent_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SecurityEvent_OBJID;

	S->poisoned = false;

	S->pid = 0;

	S->event       = NULL;
	S->coe	       = NULL;
	S->cell	       = NULL;
	S->identity    = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for parsing the pid component of a security
 * interaction event.  The pid description is in th  following clause of
 * the event:
 *
 *	pid{NN}
 *
 * Where NN is the numeric identifier of the process which executed
 * the information interaction event.
 *
 *
 * \param S	A pointer to the state information for the information
 *		interaction event.
 *
 * \param event	The object containing the event.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of parsing the event definition.  A false
 *		value indicates the parsing failed and the object.
 *		A true value indicates the object has been successfully
 *		populated.
 */

static _Bool _parse_pid(CO(SecurityEvent_State, S), CO(String, event))

{
	_Bool retn       = false,
	      have_regex = false;

	char *fp,
	     match[11];

	long int vl;

	size_t len;

	regex_t regex;

	regmatch_t regmatch[2];


	if ( regcomp(&regex, "pid\\{([^}]*)\\}", REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	fp = event->get(event);
	if ( regexec(&regex, fp, 2, regmatch, 0) == REG_NOMATCH ) {
		retn = true;
		goto done;
	}

	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	if ( len > sizeof(match) )
		ERR(goto done);
	memset(match, '\0', sizeof(match));
	memcpy(match, fp + regmatch[1].rm_so, len);

	vl = strtol(match, NULL, 0);
	if ( errno == ERANGE )
		ERR(goto done);
	if ( vl > UINT32_MAX )
		ERR(goto done);

	S->pid = vl;
	retn = true;

 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for parsing the event component of an
 * information interaction event.  The event description is in the the
 * following clause of the event:
 *
 *	evant{proc=process_name, path=pathname, pid=PID}
 *
 *
 * \param S	A pointer to the state information for the information
 *		interaction event.
 *
 * \param event	The object containing the event.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of parsing the event definition.  A false
 *		value indicates the parsing failed and the object.
 *		A true value indicates the object has been successfully
 *		populated.
 */

static _Bool _parse_event(CO(SecurityEvent_State, S), CO(String, event))

{
	_Bool retn	 = false,
	      have_regex = false;

	char *fp,
	     bufr[2];

	size_t lp,
	       len;

	regex_t regex;

	regmatch_t regmatch[2];


	/* Extract the field itself. */
	if ( regcomp(&regex, "event\\{([^}]*)\\}", REG_EXTENDED) != 0 )
		ERR(goto done);
	have_regex = true;

	fp = event->get(event);
	if ( regexec(&regex, fp, 2, regmatch, 0) != REG_OK )
		ERR(goto done);

	fp += regmatch[1].rm_so;
	len = regmatch[1].rm_eo - regmatch[1].rm_so;
	bufr[1] = '\0';

	for (lp= 0; lp < len; ++lp) {
		bufr[0] = *fp;
		S->event->add(S->event, bufr);
		++fp;
	}

	if ( S->event->poisoned(S->event) )
		ERR(goto done);
	retn = true;

 done:
	if ( have_regex )
		regfree(&regex);

	return retn;
}


/**
 * External public method.
 *
 * This method the parsing of an information interaction event in ASCII
 * form.  This method uses the COE and Cell objects to parse and aggregate
 * those components of the event.
 *
 * \param this	A pointer to the security interaction event object which
 *		is to be parsed.
 *
 * \param event	The object containing the string which is to be
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool parse(CO(SecurityEvent, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object and event state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Parse the event definition. */
	if ( !_parse_event(S, event) )
		ERR(goto done);

	/* Parse the process id. */
	if ( !_parse_pid(S, event) )
		ERR(goto done);

	/* Parse the COE and Cell components. */
	if ( !S->coe->parse(S->coe, event) )
		ERR(goto done);
	if ( !S->cell->parse(S->cell, event) )
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
 * This method the parsing of an security interaction event in ASCII
 * form.  This method uses the COE and Cell objects to parse and
 * aggregate those components of the event.
 *
 * \param this	A pointer to the security interaction event object which
 *		is to be parsed.
 *
 * \param event	The object containing the string which is to be
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the parsing.  A false value indicates the
 *		parsing failed and the object is poisoned.  A true
 *		value indicates the object has been successfully
 *		populated.
 */

static _Bool measure(CO(SecurityEvent, this))

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
	if ( !S->coe->measure(S->coe) )
		ERR(goto done);
	if ( !S->cell->measure(S->cell) )
		ERR(goto done);

	/* Compute the intersection identity/measurement. */
	if ( !bufr->add(bufr, (unsigned char * ) &length, \
			sizeof(length)) )
		ERR(goto done);
	if ( !S->coe->get_measurement(S->coe, bufr) )
		ERR(goto done);

	if ( !bufr->add(bufr, (unsigned char *) &length, \
			sizeof(length)) )
		ERR(goto done);
	if ( !S->cell->get_measurement(S->cell, bufr) )
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
 * identity/measurement of an security interaction event.  It is
 * considered to be a terminal error for the object for this function
 * to be called without previously calling the ->measurement method.
 *
 * \param this	A pointer to the COE whose characteristics are to be
 *		retrieved.
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

static _Bool get_identity(CO(SecurityEvent, this), CO(Buffer, bufr))

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
 * This method implements an accessor function for retrieving the
 * description of a security interaction event.  This is the name of
 * the COE and Cell which are involved in the interaction
 * event.
 *
 * \param this	A pointer to the COE whose characteristics are to be
 *		retrieved.
 *
 * \param bufr	The object which the event is to be loaded into.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the supplied object has a valid event description in
 *		it.  A false value indicates the object does not have
 *		a valid event.  A true value indicates the supplied
 *		object has a valid copy of this object's measurement.
 */

static _Bool get_event(CO(SecurityEvent, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->event->poisoned(S->event) )
		ERR(goto done);

	if ( !event->add(event, S->event->get(S->event)) )
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
 * This method implements an accessor function for retrieving the
 * process identifer of a security interaction event.
 *
 * \param this	A pointer to the event from which the process
 *		identifier is to be retrieved.
 *
 * \param pid	A pointer to the variable which will be loaded
 *		with the process identifier.
 *
 * \return	A boolean value is used to indicate whether or
 *		not the request for a pid was successful.  A
 *		false value indicates the object has been
 *		poisoned and is not able to return a PID,  A
 *		true value indicates the location provided by
 *		the caller contains a valid process identifier.
 */

static _Bool get_pid(CO(SecurityEvent, this), pid_t * const pid)

{
	STATE(S);


	if ( S->poisoned )
		return false;

	*pid = S->pid;
	return true;
}


/**
 * External public method.
 *
 * This method implements the generation of an ASCII formatted
 * representation of the security interaction event modeled by an
 * object.  The string generated is in the same format that is
 * interpreted by the ->parse method.
 *
 * \param this	A pointer to the information excahange object
 *		which is to be modeled.
 *
 * \param event	The object into which the formatted string is to
 *		be copied.
 */

static _Bool format(CO(SecurityEvent, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);


	/* Add the event description, COE and Cell elements. */
	event->add(event, "event{");
	event->add(event, S->event->get(S->event));
	event->add(event, "} ");

	S->coe->format(S->coe, event);

	if ( !S->cell->format(S->cell, event) )
		ERR(goto done);

	retn = true;

 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the reset of an security information event
 * object to a state which would allow the processing of a new
 * event.
 *
 * \param this	A pointer to the security interaction event object which
 *		is to be reset.
 */

static void reset(CO(SecurityEvent, this))

{
	STATE(S);

	S->poisoned = false;

	S->event->reset(S->event);
	S->coe->reset(S->coe);
	S->cell->reset(S->cell);
	S->identity->reset(S->identity);

	return;
}


/**
 * External public method.
 *
 * This method implements output of the characteristis of the interaction
 * event represented by the object.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump(CO(SecurityEvent, this))

{
	STATE(S);

	if ( S->poisoned )
		fputs("*Poisoned.\n", stdout);

	fputs("Event:\n", stdout);
	if ( S->pid != 0 )
		fprintf(stdout, "pid:\t%u\n", S->pid);
	fputs("type:\t", stdout);
	S->event->print(S->event);

	fputs("COE:\n", stdout);
	S->coe->dump(S->coe);

	fputs("\nCell:\n", stdout);
	S->cell->dump(S->cell);

 	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for an SecurityEvent object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SecurityEvent, this))

{
	STATE(S);

	WHACK(S->event);
	WHACK(S->coe);
	WHACK(S->cell);
	WHACK(S->identity);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for an SecurityEvent object.
 *
 * \return	A pointer to the initialized interaction event.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SecurityEvent NAAAIM_SecurityEvent_Init(void)

{
	Origin root;

	SecurityEvent this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SecurityEvent);
	retn.state_size   = sizeof(struct NAAAIM_SecurityEvent_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SecurityEvent_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, String, this->state->event, goto fail);
	INIT(NAAAIM, COE, this->state->coe, goto fail);
	INIT(NAAAIM, Cell, this->state->cell, goto fail);
	INIT(NAAAIM, Sha256, this->state->identity, goto fail);

	/* Method initialization. */
	this->parse	   = parse;
	this->measure	   = measure;

	this->get_identity = get_identity;
	this->get_event	   = get_event;
	this->get_pid	   = get_pid;

	this->format = format;

	this->reset = reset;
	this->dump  = dump;
	this->whack = whack;

	return this;

fail:
	WHACK(this->state->event);
	WHACK(this->state->coe);
	WHACK(this->state->cell);
	WHACK(this->state->identity);

	root->whack(root, this, this->state);
	return NULL;
}