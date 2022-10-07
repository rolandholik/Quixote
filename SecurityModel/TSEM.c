/** \file
 * This file contains the implementation of an object which manages
 * a single instance of a Turing Security Event Model (TSEM).
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
#include <sys/types.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <Gaggle.h>
#include <String.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "Base64.h"
#include "RSAkey.h"
#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"
#include "EventModel.h"


/* Default aggregate value. */
#define DEFAULT_AGGREGATE \
	"0000000000000000000000000000000000000000000000000000000000000000"

/* Object state extraction macro. */
#define STATE(var) CO(TSEM_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_TSEM_OBJID)
#error Object identifier not defined.
#endif


/** The numerical definitions for the security model load commands. */
enum {
	model_cmd_comment=1,
	model_cmd_key,
	model_cmd_base,
	model_cmd_aggregate,
	model_cmd_state,
	model_cmd_pseudonym,
	model_cmd_seal,
	model_cmd_signature,
	model_cmd_end
} security_load_commands;

/** The structure used to equate strings to numerical load commands. */
struct security_load_definition {
	int command;
	char *syntax;
	_Bool has_arg;
};

/** The list of security load commands. */
struct security_load_definition Security_cmd_list[] = {
	{model_cmd_comment,	"#",		false},
	{model_cmd_key,		"key ",		true},
	{model_cmd_base,	"base ",	true},
	{model_cmd_aggregate,	"aggregate ",	true},
	{model_cmd_state,	"state ",	true},
	{model_cmd_pseudonym,	"pseudonym ",	true},
	{model_cmd_seal,	"seal",		false},
	{model_cmd_signature,	"signature ",	true},
	{model_cmd_end,		"end",		false}
};


/** ExchangeEvent private state information. */
struct NAAAIM_TSEM_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;
	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* Flag to indicate aggregate measurement. */
	_Bool have_aggregate;

	/* Flag to indicate that a security model is being loaded. */
	_Bool loading;

	/* Flag to indicate the measurement domain has been sealed. */
	_Bool sealed;

	/* Process identifier to be disciplined. */
	pid_t discipline_pid;

	/* Model base point. */
	unsigned char base[NAAAIM_IDSIZE];

	/* Event domain instance aggregate. */
	Buffer aggregate;

	/* Canister measurement. */
	unsigned char measurement[NAAAIM_IDSIZE];

	/* Execution trajectory list. */
	Gaggle trajectory;

	/* Security state point list. */
	Gaggle points;

	/* Forensics trajectory list. */
	Gaggle forensics;

	/* TE events list. */
	Gaggle TE_events;

	/* An optional security event model. */
	EventModel model;

	/* The key and signature of a loaded security model. */
	Buffer key;
	Buffer sigdata;
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

static void _init_state(CO(TSEM_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_TSEM_OBJID;

	S->poisoned	  = false;
	S->have_aggregate = false;
	S->loading	  = false;
	S->sealed	  = false;

	S->discipline_pid = 0;

	memset(S->base, '\0', sizeof(S->base));
	memset(S->measurement, '\0', sizeof(S->measurement));

	S->aggregate	= NULL;
	S->trajectory	= NULL;
	S->points	= NULL;
	S->forensics	= NULL;
	S->TE_events	= NULL;
	S->model	= NULL;

	S->key		= NULL;
	S->sigdata	= NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for searching the current behavior map
 * to determine if this event has already been registerd.
 *
 * \param map	The object containing the current security state point
 *		list.
 *
 * \param point	The object containing the security point that is to
 *		be checked.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the point was in the current security model.  A false
 *		false value indicates the point was not found while
 *		a true value indicated the point was present.
 */

static _Bool _is_mapped(CO(Gaggle, map), CO(SecurityPoint, point))

{
	_Bool retn = false;

	size_t size = map->size(map);

	SecurityPoint cp;


	/* Verify the list contains elements and then traverse it. */
	if ( size == 0 )
		retn = false;
	map->rewind_cursor(map);

	while ( size-- ) {
		cp = GGET(map, cp);
		if ( point->equal(point, cp) ) {
			if ( !cp->is_valid(cp) )
				point->set_invalid(point);
			return true;
		}
	}

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for generating a new terminus point for a
 * linear extension measurement.  It does by extending an update value
 * with the domain identity.  This extended value is then used to extend
 * the current measurement value passed into the caller.
 *
 * \param this		A pointer to the state information of the event
 *			domain supporting the measurement.
 *
 * \param update	A pointer to the buffer containing the value
 *			to be used to extend the specified measuremet value.
 *
 * \param measurement	A pointer the buffer that contains a current
 *			measurement value that will be extended.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement was extended.  A false value indicates
 *		an error occurred while a true value indicates the
 *		measurement was successfully extended.
 */

static _Bool _extend_measurement(CO(TSEM_State, S),    \
				 CO(unsigned char *, update), \
				 unsigned char *measurement)

{
	_Bool retn = false;

	Buffer b,
	       bufr = NULL;

	Sha256 sha256 = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));

	/* Project the update into a domain specific value. */
	bufr->add(bufr, S->base, sizeof(S->base));
	bufr->add(bufr, update, NAAAIM_IDSIZE);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	/* Extend the current measurement. */
	bufr->reset(bufr);
	bufr->add(bufr, measurement, NAAAIM_IDSIZE);

	b = sha256->get_Buffer(sha256);
	bufr->add_Buffer(bufr, b);

	sha256->reset(sha256);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	memcpy(measurement, b->get(b), NAAAIM_IDSIZE);
	retn = true;

 done:
	WHACK(bufr);
	WHACK(sha256);

	return retn;
}


/**
 * External public method.
 *
 * This method implements updating the currently maintained behavioral
 * model with an information exchange event.
 *
 * \param this	A pointer to the object which is being modeled.
 *
 * \param event	The object containing the event which is to be
 *		registered.
 *
 * \param status	A pointer to a boolean value used to inform
 *			the caller as to whether or not the event was
 *			added to the current model.
 *
 * \param discipline	A pointer to a boolean value used to inform
 *			the caller as to whether or not the update
 *			requires the process to be disciplined.
 *
 * \param sealed	A poiner to a boolean value that is used to
 *			advise the caller whether or not the model
 *			was sealed.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the the event was registered.  A false value indicates
 *		a failure while a true value indicates the model
 *		was updated.
 */

static _Bool update(CO(TSEM, this), CO(SecurityEvent, event), _Bool *status, \
		    _Bool *discipline, _Bool *sealed)

{
	STATE(S);

	_Bool retn	    = false,
	      added	    = false,
	      release_point = true;

	Buffer point = NULL;

	Gaggle list;

	SecurityPoint cp = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->loading )
		ERR(goto done);


	/* Use a default aggregate measurement if not specified. */
	if ( !S->have_aggregate ) {
		if ( !S->aggregate->add_hexstring(S->aggregate, \
						  DEFAULT_AGGREGATE) )
			ERR(goto done);
		if ( !_extend_measurement(S, S->aggregate->get(S->aggregate), \
					  S->measurement) )
			ERR(goto done);

		S->aggregate->reset(S->aggregate);
		if ( !S->aggregate->add(S->aggregate, S->measurement, \
					sizeof(S->measurement)) )
			ERR(goto done);

		S->have_aggregate = true;
	}


	/* Evaluate the event in the contex of the current security model. */
	if ( S->model != NULL ) {
		if ( !S->model->evaluate(S->model, event) )
			ERR(goto done);
	}


	/*
	 * Measure the current security exchange event to obtain the
	 * security state point that will be added to the model.
	 */
	INIT(HurdLib, Buffer, point, ERR(goto done));

	if ( !event->measure(event) )
		ERR(goto done);
	if ( !event->get_identity(event, point) )
		ERR(goto done);
	if ( !event->get_pid(event, &S->discipline_pid) )
		ERR(goto done);

	INIT(NAAAIM, SecurityPoint, cp, ERR(goto done));
	cp->add(cp, point);


	/* Register the security state point. */
	if ( _is_mapped(S->points, cp) ) {
		retn	   = true;
		*status	   = false;
		goto done;
	}


	/* Update the platform measurement. */
	if ( !_extend_measurement(S, cp->get(cp), S->measurement) )
		ERR(goto done);


	/* Add the security state point. */
	if ( !GADD(S->points, cp) )
		ERR(goto done);
	release_point = false;

	if ( S->sealed ) {
		cp->set_invalid(cp);
		list = S->forensics;
		if ( !event->get_pid(event, &S->discipline_pid) )
			ERR(goto done);
	}
	else
		list = S->trajectory;

	if ( !GADD(list, event) )
		ERR(goto done);

	retn  = true;
	added = true;

 done:
	if ( retn ) {
		*status	    = added;
		*discipline = !cp->is_valid(cp);
		*sealed	    = S->sealed;
	}

	WHACK(point);
	if ( release_point )
		WHACK(cp);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal public method.
 *
 * This method implements updating the currently maintained behavioral
 * model with a specific security state point.
 *
 * \param this	A pointer to the object that is being modeled.
 *
 * \param point	An object containing the security state point that is
 *		is to be added to the behavioral map.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the security point was registered.  A false value indicates
 *		a failure while a true value indicates the model
 *		was updated.
 */

static _Bool _update_map(CO(TSEM, this), CO(Buffer, bpoint))

{
	STATE(S);

	_Bool retn = false;

	SecurityPoint cp = NULL;


	/* Validate object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bpoint->poisoned(bpoint) )
		ERR(goto done);
	if ( bpoint->size(bpoint) != NAAAIM_IDSIZE )
		ERR(goto done);
	if ( S->sealed )
		ERR(goto done);


	/* Register the security state point. */
	INIT(NAAAIM, SecurityPoint, cp, ERR(goto done));

	cp->add(cp, bpoint);
	if ( _is_mapped(S->points, cp) ) {
		retn = true;
		goto done;
	}


	/* Update the platform measurement. */
	if ( !_extend_measurement(S, cp->get(cp), S->measurement) )
		ERR(goto done);


	/* Add the security state point. */
	if ( !GADD(S->points, cp) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		WHACK(cp);

	return retn;
}


/**
 * Internal private function.
 *
 * This function encapsulates the addition of a line from a model file
 * to the Buffer object that will be hashed to generate the signature
 * for the model.
 *
 * \param bufr		The state information for the model object.
 *
 * \param line		The object containing the line to add to the
 *			file.
 *
 * \return	A boolean value is used to indicate the status of the
 *		addition of the line.  A false value indicates the
 *		addition failed while a true value indicates the
 *		contents of the line had been added to the buffer.
 */

static _Bool _add_entry(CO(Buffer, bufr), CO(String, line))

{
	_Bool retn = false;


	if ( !bufr->add(bufr, (void *) line->get(line), line->size(line) + 1) )
		ERR(goto done);

	retn = true;


 done:
	return retn;

}


/**
 * Internal private function.
 *
 * This function carries out the validation of a signed security model.
 *
 * \param key		The object containing
 *			model over which the signature is generated.
 *
 * \param sigdata	The object containing the contents of the
 *			security model in a form suitable for computing
 *			the hash signature.
 *
 * \param sig		The Base64 encoded signature.
 *
 * \param valid		A pointer to the boolean value that will be
 *			loaded with the result of the signature
 *			validation.
 *
 * \return	A boolean value is used to indicate the status of the
 *		computation of the signature.  A false value indicates
 *		an error was encountered while computing the signature.
 *		A true value indicates the signature was calculated
 *		and the variable pointed to by the status variable
 *		contains the status of the signature.
 */

static _Bool _verify_model(CO(Buffer, key), CO(Buffer, sigdata), char * sig, \
			   _Bool *valid)

{
	_Bool retn = false;

	Buffer signature = NULL;

	String str = NULL;

	Base64 base64 = NULL;

	RSAkey rsakey = NULL;


	/* Load the key that was provided. */
	INIT(HurdLib, String, str, ERR(goto done));
	if ( !str->add(str, (char *) key->get(key)) )
		ERR(goto done);

	INIT(NAAAIM, Base64, base64, ERR(goto done));
	key->reset(key);
	if ( !base64->decode(base64, str, key) )
		ERR(goto done);

	INIT(NAAAIM, RSAkey, rsakey, ERR(goto done));
	if ( !rsakey->load_public(rsakey, key) )
		ERR(goto done);


	/* Decode and verify the signature. */
	str->reset(str);
	if ( !str->add(str, sig) )
		ERR(goto done);

	INIT(HurdLib, Buffer, signature, ERR(goto done));
	if ( !base64->decode(base64, str, signature) )
		ERR(goto done);

	if ( !rsakey->verify(rsakey, signature, sigdata, valid) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(signature);
	WHACK(str);
	WHACK(base64);
	WHACK(rsakey);

	return retn;

}


/**
 * External public method.
 *
 * This method implements the loading of entries into a security model.
 *
 * \param this		A pointer to the object that is being modeled.
 *
 * \param entry		An object that contains the description of the
 *			entry that is to be entered into the security
 *			model.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the entry was successfully loaded into the security
 *		model.  A false value indicates a failure occurred while
 *		a true value indicates the security model was
 *		successfully updated.
 */

static _Bool load(CO(TSEM, this), CO(String, entry))

{
	STATE(S);

	_Bool retn	= false,
	      sig_valid = false;

	char *arg = NULL;

	struct security_load_definition *dp;

	Buffer bufr = NULL;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Locate the load command being requested. */
	for (dp= Security_cmd_list; dp->command <= model_cmd_end; ++dp) {
		if ( strncmp(dp->syntax, entry->get(entry), \
			     strlen(dp->syntax)) == 0 )
			break;
	}
	if ( dp->command > model_cmd_end )
		ERR(goto done);

	if ( (dp->command != model_cmd_signature) && !S->loading )
		S->loading = true;


	/* Get the start of command argument. */
	if ( dp->has_arg ) {
		arg = entry->get(entry) + strlen(dp->syntax);
		if ( *arg == '\0' )
			ERR(goto done);
	}


	/* Implement the command. */
	if ( S->sigdata == NULL )
		INIT(HurdLib, Buffer, S->sigdata, ERR(goto done));

	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	switch ( dp->command ) {
		case model_cmd_comment:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);
			break;

		case model_cmd_key:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);

			if ( S->key != NULL )
				ERR(goto done);
			INIT(HurdLib, Buffer, S->key, ERR(goto done));
			if ( !S->key->add(S->key, (void *) arg, \
					  strlen(arg) + 1) )
				ERR(goto done);
			break;

		case model_cmd_base:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);

			if ( !bufr->add_hexstring(bufr, arg) )
				ERR(goto done);
			memcpy(S->base, bufr->get(bufr), sizeof(S->base));
			break;

		case model_cmd_aggregate:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);

			if ( !bufr->add_hexstring(bufr, arg) )
				ERR(goto done);
			if ( !this->set_aggregate(this, bufr) )
				ERR(goto done);
			break;

		case model_cmd_state:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);

			if ( !bufr->add_hexstring(bufr, arg) )
				ERR(goto done);
			if ( !_update_map(this, bufr) )
				ERR(goto done);
			break;

		case model_cmd_pseudonym:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);

			if ( S->model == NULL )
				INIT(NAAAIM, EventModel, S->model, \
				     ERR(goto done));

			if ( !bufr->add_hexstring(bufr, arg) )
				ERR(goto done);
			if ( !S->model->add_pseudonym(S->model, bufr) )
				ERR(goto done);
			break;

		case model_cmd_seal:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);

			this->seal(this);
			break;

		case model_cmd_signature:
			if ( (S->sigdata == NULL) || (S->key == NULL) )
				ERR(goto done);

			if ( !_verify_model(S->key, S->sigdata, arg, \
					    &sig_valid) )
				ERR(goto done);
			if ( !sig_valid )
				ERR(goto done);
			break;

		case model_cmd_end:
			if ( !_add_entry(S->sigdata, entry) )
				ERR(goto done);

			S->loading = false;
			break;
	}

	retn = true;


 done:
	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method implements initializing the model with an aggregate
 * measurement value.  The aggregate value typically reflects a
 * hardware root of trust value.
 *
 * \param this	A pointer to the canister whose aggregate value is
 *		to be set.
 *
 * \param bufr	The object containing the aggregate value to be
 *		used.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the aggregate measurement was successfully set.  A
 *		false value indicate a failure in returning measurement
 *		while a true value indicates the object contains a valid
 *		measurement.
 */

static _Bool set_aggregate(CO(TSEM, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	uint8_t measurement[NAAAIM_IDSIZE];


	/* Verify object status and aggregate state. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->sealed ) {
		retn = true;
		goto done;
	}


	/* Compute the host specific aggregate value. */
	memset(measurement, '\0', sizeof(measurement));
	if ( !_extend_measurement(S, bufr->get(bufr), measurement) )
		ERR(goto done);

	if ( S->have_aggregate ) {
		if ( memcmp(S->aggregate->get(S->aggregate), measurement, \
			    sizeof(measurement)) == 0 ) {
			retn = true;
			goto done;
		}
		S->aggregate->reset(S->aggregate);
	}

	memcpy(S->measurement, measurement, sizeof(S->measurement));
	if ( !S->aggregate->add(S->aggregate, S->measurement, \
				sizeof(S->measurement)) )
		ERR(goto done);

	retn		  = true;
	S->have_aggregate = true;


 done:
	if ( !retn )
		S->poisoned = true;

	memset(measurement, '\0', sizeof(measurement));

	return retn;
}


/**
 * External public method.
 *
 * This method implements adding a TE event to the current model.
 *
 * \param this	A pointer to the canister to which an event is to be
 *		added.
 *
 * \param event	The object containing the event description to be
 *		added.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the aggregate measurement was successfully set.  A
 *		false value indicate a failure in returning measurement
 *		while a true value indicates the object contains a valid
 *		measurement.
 */

static _Bool add_TSEM_event(CO(TSEM, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);

	if ( !GADD(S->TE_events, event) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the TSEM events which
 * have been injected into the model.  This method is designed to be
 * called repeatedly until the list of TE events is completely traversed.
 * The traversal can be reset by calling the ->rewind_TE_event method.
 *
 * \param this	A pointer to the canister whose TE events are to be
 *		retrieved.
 *
 * \param event	The object which the event will be copied to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid event was returned.  A false value
 *		indicates a failure occurred and a valid event is
 *		not available.  A true value indicates the event
 *		object contains a valid value.
 *
 *		The end of the event list is signified by a NULL
 *		event object being set.
 */

static _Bool get_TSEM_event(CO(TSEM, this), String * const event)

{
	STATE(S);

	_Bool retn = true;

	void *p;

	String return_event = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Verify that we are in the bounds of the list. */
	if ( (p = S->TE_events->get(S->TE_events)) == NULL ) {
		retn = true;
		goto done;
	}

	return_event = GPTR(p, return_event);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	else
		*event = return_event;

	return retn;
}


/**
 * External public method.
 *
 * This method implements returning the number of TE events in the
 * current security model.
 *
 * \param this	A pointer to the object whose IA event size is to
 *		be returned.
 *
 * \return	The size of the AI events list.
 *
 */

static void TSEM_rewind_event(CO(TSEM, this))

{
	STATE(S);

	S->TE_events->rewind_cursor(S->TE_events);
	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of TSEM events in the
 * current security model
 *
 * \param this	A pointer to the object whose event size is to
 *		be returned.
 *
 * \return	The size of the events list.
 *
 */

static size_t TSEM_events_size(CO(TSEM, this))

{
	STATE(S);

	return S->TE_events->size(S->TE_events);
}


/**
 * External public method.
 *
 * This method is an accessor method for accessing the currrent
 * measurement of the model.
 *
 * \param this	A pointer to the canister whose measurement is to be
 *		retrieved.
 *
 * \param bufr	The object which the measurement will be returned in.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid measurement was returned.  A false value
 *		indicate a failure in returning measurement while a
 *		true value indicates the object contains a valid
 *		measurement.
 */

static _Bool get_measurement(CO(TSEM, this), CO(Buffer, bufr))

{
	STATE(S);

	return bufr->add(bufr, S->measurement, sizeof(S->measurement));
}


/**
 * Internal private function.
 *
 * This function implements the sort comparison function for the
 * ->get_state method.
 *
 * \param p1	A pointer to the first point to be compared.
 *
 * \param p2	A pointer to the second point to be compared.
 *
 * \return	An integer value is returned to reflect the lexicographic
 *		order of the two points.  A value less then zero indicates
 *		the first point is less then the second point while a
 *		value greater then zero indicates the first port is larger
 *		then the second point.
 */

static int _state_sort(const void *a1, const void *a2)

{
	int retn = 0;

	uint8_t lp;

	SecurityPoint cp1 = *(SecurityPoint *) a1,
		      cp2 = *(SecurityPoint *) a2;

	unsigned char *p1 = cp1->get(cp1),
		      *p2 = cp2->get(cp2);

	Buffer bufr = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	for (lp= 0; lp < NAAAIM_IDSIZE; ++lp) {
		if ( *p1 == *p2 ) {
			++p1;
			++p2;
			continue;
		}
		if ( *p1 < *p2 )
			retn = -1;
		else
			retn = 1;
		goto done;
	}


 done:
	WHACK(bufr);

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for generating and returning the
 * current state of the system.
 *
 * \param this	A pointer to the canister whose state is to be
 *		retrieved.
 *
 * \param out	The object which the state will be returned in.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid state value was returned.  A false value
 *		indicates a failure in generating the state while a
 *		true value indicates the output objects contains a
 *		valid state value.
 */

static _Bool get_state(CO(TSEM, this), CO(Buffer, out))

{
	STATE(S);

	_Bool retn = false;

	unsigned char state[NAAAIM_IDSIZE];

	size_t cnt;

	void *p;

	Buffer points = NULL;

	SecurityPoint *ep,
		      event;


	/* Clone the list of security state points. */
	INIT(HurdLib, Buffer, points, ERR(goto done));

	cnt = S->points->size(S->points);
	S->points->rewind_cursor(S->points);

	while ( cnt-- ) {
		p = S->points->get(S->points);
		if ( !points->add(points, p, sizeof(void *)) )
			ERR(goto done);
	}


	/* Sort the points. */
	cnt = S->points->size(S->points);
	qsort(points->get(points), cnt, sizeof(SecurityPoint), _state_sort);

	ep = (SecurityPoint *) points->get(points);
	memcpy(state, S->aggregate->get(S->aggregate), sizeof(state));

	while ( cnt-- ) {
		event = *ep;
		if ( !_extend_measurement(S, event->get(event), state) )
			ERR(goto done);
		++ep;
	}

	if ( !out->add(out, state, sizeof(state)) )
		ERR(goto done);
	retn = true;


 done:
	memset(state, '\0', sizeof(state));
	WHACK(points);

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for accessing the process identifier
 * of the process which has engaged in an extra-dimensional behavior
 * event.
 *
 * \param this	A pointer to the canister whose pid is to be returned.
 *
 * \param pid	A pointer to the location where the pid is to be
 *		storaged.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid pid was returned.  A false value
 *		indicate a failure in returning the pid value while a
 *		true value indicates the destination contains a valid
 *		process ID.
 */

static _Bool discipline_pid(CO(TSEM, this), pid_t * const pid)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	*pid = S->discipline_pid;
	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the information
 * exchange events which comprise the model.  This method is designed
 * to be called repeatedly until the list of events is completely
 * traversed.  The traversal can be reset by calliong the
 * ->rewind_event method.
 *
 * \param this	A pointer to the canister whose events are to be
 *		retrieved.
 *
 * \param event	The object which the event will be copied to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid event was returned.  A false value
 *		indicates a failure occurred and a valid event is
 *		not available.  A true value indicates the event
 *		object contains a valid value.
 *
 *		The end of the event list is signified by a NULL
 *		event object being set.
 */

static _Bool get_event(CO(TSEM, this), SecurityEvent * const event)

{
	STATE(S);

	_Bool retn = true;

	void *p;

	SecurityEvent return_event = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Verify that we are in the bounds of the list. */
	if ( (p = S->trajectory->get(S->trajectory)) == NULL ) {
		retn = true;
		goto done;
	}

	return_event = GPTR(p, return_event);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	else
		*event = return_event;

	return retn;
}


/**
 * External public method.
 *
 * This method resets the trajector cursor.
 *
 * \param this	A pointer to the canister whose events are to be
 *		retrieved.
 *
 * \return	No return value is defined.
 */

static void rewind_event(CO(TSEM, this))

{
	STATE(S);

	S->trajectory->rewind_cursor(S->trajectory);
	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of event in the
 * security domain.
 *
 * \param this	A pointer to the object whose event size is to be returned.
 *
 * \return	The size of the events list.
 *
 */

static size_t trajectory_size(CO(TSEM, this))

{
	STATE(S);

	return S->trajectory->size(S->trajectory);
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the security points
 * which comprise the security model implemented in an object.  This
 * method is designed to be called repeatedly until the list of points
 * is completely traversed.  The traversal can be reset by calling the
 * ->rewind_points method.
 *
 * \param this	A pointer to the object whose points are to be
 *		retrieved.
 *
 * \param event	The object which the point will be copied to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a security state point was returned.  A false value
 *		indicates a failure occurred and a valid point is
 *		not available.  A true value indicates the point
 *		object contains a valid value.
 *
 *		The end of the point list is signified by a NULL
 *		point object being set.
 */

static _Bool get_point(CO(TSEM, this), SecurityPoint * const point)

{
	STATE(S);

	_Bool retn = true;

	void *p;

	SecurityPoint return_point = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Verify that we are in the bounds of the list. */
	if ( (p = S->points->get(S->points)) == NULL ) {
		retn = true;
		goto done;
	}

	return_point = GPTR(p, return_point);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	else
		*point = return_point;

	return retn;
}


/**
 * External public method.
 *
 * This method resets the security state point retrieval cursor.
 *
 * \param this	A pointer to the canister whose points are to be
 *		retrieved.
 *
 * \return	No return value is defined.
 */

static void rewind_points(CO(TSEM, this))

{
	STATE(S);

	S->points->rewind_cursor(S->points);
	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of points in the
 * current behavioral map.
 *
 * \param this	A pointer to the object whose behavioral map
 *		size is to be returned.
 *
 * \return	The size of the forensics trajectory list.
 *
 */

static size_t points_size(CO(TSEM, this))

{
	STATE(S);

	return S->points->size(S->points);
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the exchange
 * events which have been registered for the canister being modeled.
 * This method is designed to be called repeatedly until the list of
 * events is completely traversed.  The traversal can be reset by
 * calling the ->rewind_forensics method.
 *
 * \param this	A pointer to the canister whose forensics events
 *		are to be retrieved.
 *
 * \param event	The object which the event will be copied to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a valid event was returned.  A false value
 *		indicates a failure occurred and a valid event is
 *		not available.  A true value indicates the event
 *		object contains a valid value.
 *
 *		The end of the event list is signified by a NULL
 *		event object being set.
 */

static _Bool get_forensics(CO(TSEM, this), SecurityEvent * const event)

{
	STATE(S);

	_Bool retn = true;

	void *p;

	SecurityEvent return_event = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Verify that we are in the bounds of the list. */
	if ( (p = S->forensics->get(S->forensics)) == NULL ) {
		retn = true;
		goto done;
	}
	return_event = GPTR(p, return_event);
	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;
	else
		*event = return_event;

	return retn;
}


/**
 * External public method.
 *
 * This method resets the forensics cursor.
 *
 * \param this	A pointer to the canister whose forensics event
 *		cursor is to be reset.
 *
 * \return	No return value is defined.
 */

static void rewind_forensics(CO(TSEM, this))

{
	STATE(S);

	S->forensics->rewind_cursor(S->forensics);
	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of events in the
 * behavioral forensics trajectory.
 *
 * \param this	A pointer to the object whose forensics trajectory
 *		size is to be returned.
 *
 * \return	The size of the forensics trajectory list.
 *
 */

static size_t forensics_size(CO(TSEM, this))

{
	STATE(S);

	return S->forensics->size(S->forensics);
}


/**
 * External public method.
 *
 * This method implements output of the information exchange events in
 * the current behavioral model in verbose form.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump_events(CO(TSEM, this))

{
	STATE(S);

	size_t lp = 1;

	SecurityEvent event;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}


	/* Traverse and dump the trajectory path. */
	rewind_event(this);
	do {
		if ( !get_event(this, &event) ) {
			fputs("Error retrieving event.\n", stdout);
			return;
		}
		if ( event != NULL ) {
			fprintf(stdout, "Point: %zu\n", lp++);
			event->dump(event);
			fputs("\n\n", stdout);
		}
	} while ( event != NULL );


	return;
}


/**
 * External public method.
 *
 * This method implements output of the information exchange events
 * which are registered for the behavioral model.
 *
 * \param this	A pointer to the object whose forensics state is to be
 *		dumped.
 */

static void dump_forensics(CO(TSEM, this))

{
	STATE(S);

	size_t lp = 1;

	SecurityEvent event;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}


	/* Traverse and dump the trajectory path. */
	rewind_forensics(this);
	do {
		if ( !get_forensics(this, &event) ) {
			fputs("Error retrieving event.\n", stdout);
			return;
		}
		if ( event != NULL ) {
			fprintf(stdout, "Point: %zu\n", lp++);
			event->dump(event);
			fputs("\n\n", stdout);
		}
	} while ( event != NULL );


	return;
}


/**
 * External public method.
 *
 * This method implements output of the information exchange events in
 * the current behavioral model in verbose form.
 *
 * \param this	A pointer to the object whose identity state is to be
 *		dumped.
 */

static void dump_points(CO(TSEM, this))

{
	STATE(S);

	Buffer bufr = NULL;

	SecurityPoint point;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}


	/* Traverse and dump the points. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	rewind_points(this);
	do {
		if ( !get_point(this, &point) ) {
			fputs("Error retrieving event.\n", stdout);
			return;
		}
		if ( point != NULL ) {
			if ( !bufr->add(bufr, point->get(point), \
					NAAAIM_IDSIZE) )
				ERR(goto done);
			bufr->print(bufr);
			bufr->reset(bufr);
		}
	} while ( point != NULL );


 done:
	WHACK(bufr);

	return;
}


/**
 * External public method.
 *
 * This method implements sealing the behavioral model in its current
 * state.  Sealing the model implies that any additional events which
 * are not in the behavioral map constitute forensic violations for
 * the system being modeled.
 *
 * \param this	A pointer to the object which is to be sealed.
 *
 */

static void seal(CO(TSEM, this))

{
	this->state->sealed = true;
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for an ExchangeEvent object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(TSEM, this))

{
	STATE(S);


	WHACK(S->aggregate);

	GWHACK(S->trajectory, SecurityEvent);
	WHACK(S->trajectory);

	GWHACK(S->forensics, SecurityEvent);
	WHACK(S->forensics);

	GWHACK(S->points, SecurityPoint);
	WHACK(S->points);

	GWHACK(S->TE_events, String);
	WHACK(S->TE_events);

	WHACK(S->model);

	WHACK(S->key);
	WHACK(S->sigdata);

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

extern TSEM NAAAIM_TSEM_Init(void)

{
	Origin root;

	TSEM this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_TSEM);
	retn.state_size   = sizeof(struct NAAAIM_TSEM_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_TSEM_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->aggregate, goto fail);
	INIT(HurdLib, Gaggle, this->state->trajectory, goto fail);
	INIT(HurdLib, Gaggle, this->state->points, goto fail);
	INIT(HurdLib, Gaggle, this->state->forensics, goto fail);
	INIT(HurdLib, Gaggle, this->state->TE_events, goto fail);

	/* Method initialization. */
	this->update	 = update;
	this->load	 = load;

	this->set_aggregate   = set_aggregate;

	this->add_TSEM_event    = add_TSEM_event;
	this->get_TSEM_event    = get_TSEM_event;
	this->TSEM_events_size  = TSEM_events_size;
	this->TSEM_rewind_event = TSEM_rewind_event;

	this->get_measurement = get_measurement;
	this->get_state	      = get_state;
	this->discipline_pid  = discipline_pid;

	this->get_event	       = get_event;
	this->rewind_event     = rewind_event;
	this->trajectory_size  = trajectory_size;

	this->get_point     = get_point;
	this->rewind_points = rewind_points;
	this->points_size   = points_size;

	this->get_forensics	= get_forensics;
	this->rewind_forensics	= rewind_forensics;
	this->forensics_size	= forensics_size;

	this->dump_events    = dump_events;
	this->dump_points  = dump_points;
	this->dump_forensics = dump_forensics;

	this->seal  = seal;
	this->whack = whack;

	return this;

fail:
	WHACK(this->state->aggregate);
	WHACK(this->state->trajectory);
	WHACK(this->state->points);

	root->whack(root, this, this->state);
	return NULL;
}
