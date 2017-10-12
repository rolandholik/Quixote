/** \file
 * This file contains the implementation of an object which manages
 * a single instance of an iso-identity behavioral model.
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
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "ExchangeEvent.h"
#include "ISOidentity.h"


/* Default aggregate value. */
#define DEFAULT_AGGREGATE \
	"0000000000000000000000000000000000000000000000000000000000000000"

/* Object state extraction macro. */
#define STATE(var) CO(ISOidentity_State, var) = this->state

/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_ISOidentity_OBJID)
#error Object identifier not defined.
#endif


/** ExchangeEvent private state information. */
struct NAAAIM_ISOidentity_State
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

	/* Canister identity. */
	unsigned char hostid[NAAAIM_IDSIZE];

	/* Canister measurement. */
	unsigned char measurement[NAAAIM_IDSIZE];

	/* Trajectory map. */
	Buffer trajectory;

	/* Behavioral contour map. */
	Buffer contours;
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

static void _init_state(CO(ISOidentity_State, S))

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_ISOidentity_OBJID;

	S->poisoned	  = false;
	S->have_aggregate = false;

	memset(S->hostid, '\0', sizeof(S->hostid));
	memset(S->measurement, '\0', sizeof(S->measurement));

	S->trajectory = NULL;
	S->contours   = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for searching the current behavior map
 * to determine if this event has already been registerd.
 *
 * \param map	The object containing the current behavioral contour
 *		map.
 *
 * \param point	The object containing the contour point which is to
 *		be checked.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the point was in the current behavioral map.  A false
 *		false value indicates the point was not found while
 *		a true value indicated the point was present.
 */

static _Bool _is_mapped(CO(Buffer, map), CO(Buffer, point))

{
	_Bool retn = false;

	size_t cnt = map->size(map) / sizeof(Buffer);

	Buffer *b = (Buffer *) map->get(map);


	while ( cnt-- ) {
		if ( (*b)->equal((*b), point) )
			return true;
		b += 1;
	}

	return retn;
}


/**
 * Internal private method.
 *
 * This method is responsible for updating the measurement value of
 * the behavioral model.  It does this by extending a measurement
 * value with the host identity of the canister.  This extended value
 * is then used to extend the current measurement value.
 *
 * \param map		The object containing the current behavioral
 *			contour map.
 *
 * \param update	The object containing the value which is to
 *			be used to extend the measurement state of
 *			the model.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the measurement was updated.  A false value indicates
 *		an error occurred while a true value indicates the
 *		measurement was successfully extended.
 */

static _Bool _update_measurement(CO(ISOidentity_State, S), CO(Buffer, update))

{
	_Bool retn = false;

	Buffer b,
	       bufr = NULL;

	SHA256 sha256 = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, SHA256, sha256, ERR(goto done));

	/* Project the update into a host specific domain. */
	bufr->add(bufr, S->hostid, sizeof(S->hostid));
	bufr->add_Buffer(bufr, update);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	/* Extend the canister measurement. */
	bufr->reset(bufr);
	bufr->add(bufr, S->measurement, sizeof(S->measurement));

	b = sha256->get_Buffer(sha256);
	bufr->add_Buffer(bufr, b);

	sha256->reset(sha256);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	memcpy(S->measurement, b->get(b), sizeof(S->measurement));
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
 * \param status	A pointer to a boolean flag  used to inform
 *			the caller as to whether or not the event was
 *			added to the current model.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the the event was registered.  A false value indicates
 *		a failure while a true value indicates the model
 *		was updated.
 */

static _Bool update(CO(ISOidentity, this), CO(ExchangeEvent, event), \
		    _Bool *status)

{
	STATE(S);

	_Bool retn = false;

	Buffer point = NULL;


	/* Verify object status and input. */
	if ( S->poisoned )
		ERR(goto done);


	/* Use a default aggregate measurement if not specified. */
	INIT(HurdLib, Buffer, point, ERR(goto done));
	if ( !S->have_aggregate ) {
		if ( !point->add_hexstring(point, DEFAULT_AGGREGATE) )
			ERR(goto done);
		if ( !_update_measurement(S, point) )
			ERR(goto done);
		S->have_aggregate = true;
		point->reset(point);
	}


	/*
	 * Get the current information exchange event identity which is
	 * the behavioral map contour point which will be processed.
	 */
	if ( !event->get_identity(event, point) )
		ERR(goto done);


	/* Register the contour point. */
	if ( _is_mapped(S->contours, point) ) {
		*status = false;
		retn = true;
		goto done;
	}

	/* Add the event and contour point. */
	if ( !S->trajectory->add(S->trajectory, (unsigned char *) &event, \
				 sizeof(ExchangeEvent)) )
		ERR(goto done);
	if ( !S->contours->add(S->contours, (unsigned char *) &point, \
			       sizeof(Buffer)) )
		ERR(goto done);
	*status = true;

	/* Update the platform measurement. */
	if ( !_update_measurement(S, point) )
		retn = false;
	else
		retn = true;

	return retn;

 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(point);
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

static _Bool set_aggregate(CO(ISOidentity, this), CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( S->have_aggregate )
		ERR(goto done);

	if ( !_update_measurement(S, bufr) )
		ERR(goto done);

	retn		  = true;
	S->have_aggregate = true;

 done:
	if ( !retn )
		S->poisoned = true;
	return retn;
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

static _Bool get_measurement(CO(ISOidentity, this), CO(Buffer, bufr))

{
	STATE(S);

	return bufr->add(bufr, S->measurement, sizeof(S->measurement));
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

static void dump_events(CO(ISOidentity, this))

{
	STATE(S);

	size_t lp,
	       cnt;

	ExchangeEvent *event;


	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}

	cnt   = S->trajectory->size(S->trajectory) / sizeof(ExchangeEvent);
	event = (ExchangeEvent *) S->trajectory->get(S->trajectory);

	for (lp= 0; lp < cnt; ++lp ) {
		fprintf(stdout, "Point: %zu\n", lp+1);
		(*event)->dump((*event));
		event += 1;
		fputs("\n\n", stdout);
	}

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

static void dump_contours(CO(ISOidentity, this))

{
	STATE(S);

	size_t cnt = S->contours->size(S->contours) / sizeof(Buffer);

	Buffer *contour = (Buffer *) S->contours->get(S->contours);


	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}

	while ( cnt-- ) {
		(*contour)->print((*contour));
		contour += 1;
	}

	return;
}


#define GWHACK(type, var) {			\
	size_t i=var->size(var) / sizeof(type);	\
	type *o=(type *) var->get(var);		\
	while ( i-- ) {				\
		(*o)->whack((*o));		\
		o+=1;				\
	}					\
}


/**
 * External public method.
 *
 * This method implements a destructor for an ExchangeEvent object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(ISOidentity, this))

{
	STATE(S);


	GWHACK(ExchangeEvent, S->trajectory);
	WHACK(S->trajectory);

	GWHACK(Buffer, S->contours);
	WHACK(S->contours);

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

extern ISOidentity NAAAIM_ISOidentity_Init(void)

{
	Origin root;

	ISOidentity this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_ISOidentity);
	retn.state_size   = sizeof(struct NAAAIM_ISOidentity_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_ISOidentity_OBJID,
			 &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */
	INIT(HurdLib, Buffer, this->state->trajectory, goto fail);
	INIT(HurdLib, Buffer, this->state->contours, goto fail);

	/* Method initialization. */
	this->update = update;

	this->set_aggregate   = set_aggregate;
	this->get_measurement = get_measurement;

	this->dump_events   = dump_events;
	this->dump_contours = dump_contours;
	this->whack	   = whack;

	return this;

fail:
	WHACK(this->state->trajectory);
	WHACK(this->state->contours);

	root->whack(root, this, this->state);
	return NULL;
}
