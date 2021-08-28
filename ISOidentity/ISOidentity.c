/** \file
 * This file contains the implementation of an object which manages
 * a single instance of an iso-identity behavioral model.
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
#include <String.h>

#include "NAAAIM.h"
#include "SHA256.h"
#include "ContourPoint.h"
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

	/* Flag to indicate the measurement domain has been sealed. */
	_Bool sealed;

	/* Process identifier to be disciplined. */
	pid_t discipline_pid;

	/* Canister identity. */
	unsigned char hostid[NAAAIM_IDSIZE];

	/* Event domain instance aggregate. */
	unsigned char domain_aggregate[NAAAIM_IDSIZE];

	/* Canister measurement. */
	unsigned char measurement[NAAAIM_IDSIZE];

	/* The size of the behavior map. */
	size_t size;

	/* Trajectory map. */
	size_t trajectory_cursor;
	Buffer trajectory;

	/* Behavioral contour map. */
	size_t contours_cursor;
	Buffer contours;

	/* Forensics event map. */
	size_t forensics_cursor;
	Buffer forensics;

	/* AI events. */
	size_t ai_events_cursor;
	Buffer ai_events;
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
	S->sealed	  = false;

	S->discipline_pid = 0;

	memset(S->hostid, '\0', sizeof(S->hostid));
	memset(S->domain_aggregate, '\0', sizeof(S->domain_aggregate));
	memset(S->measurement, '\0', sizeof(S->measurement));

	S->size = 0;

	S->trajectory	     = NULL;
	S->trajectory_cursor = 0;

	S->contours	   = NULL;
	S->contours_cursor = 0;

	S->ai_events	    = NULL;
	S->ai_events_cursor = 0;

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

static _Bool _is_mapped(CO(Buffer, map), CO(ContourPoint, point))

{
	_Bool retn = false;

	size_t cnt = map->size(map) / sizeof(ContourPoint);

	ContourPoint *cp = (ContourPoint *) map->get(map);


	while ( cnt-- ) {
		if ( point->equal(point, *cp) ) {
			if ( !(*cp)->is_valid((*cp)) )
				point->set_invalid(point);
			return true;
		}
		cp += 1;
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

static _Bool _extend_measurement(CO(ISOidentity_State, S),    \
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
	bufr->add(bufr, S->hostid, sizeof(S->hostid));
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
 * \return	A boolean value is used to indicate whether or not
 *		the the event was registered.  A false value indicates
 *		a failure while a true value indicates the model
 *		was updated.
 */

static _Bool update(CO(ISOidentity, this), CO(ExchangeEvent, event), \
		    _Bool *status, _Bool *discipline)

{
	STATE(S);

	_Bool retn	    = false,
	      added	    = false,
	      release_point = true;

	Buffer list,
	       point = NULL;

	ContourPoint cp = NULL;


	/* Verify object status and input. */
	if ( S->poisoned )
		ERR(goto done);


	/* Use a default aggregate measurement if not specified. */
	INIT(HurdLib, Buffer, point, ERR(goto done));
	if ( !S->have_aggregate ) {
		if ( !point->add_hexstring(point, DEFAULT_AGGREGATE) )
			ERR(goto done);
		if ( !_extend_measurement(S, point->get(point), \
					  S->measurement) )
			ERR(goto done);
		memcpy(S->domain_aggregate, S->measurement, \
		       sizeof(S->domain_aggregate));
		S->have_aggregate = true;
		point->reset(point);
	}


	/*
	 * Get the current information exchange event identity which is
	 * the behavioral map contour point which will be processed.
	 */
	if ( !event->get_identity(event, point) )
		ERR(goto done);
	if ( !event->get_pid(event, &S->discipline_pid) )
		ERR(goto done);

	INIT(NAAAIM, ContourPoint, cp, ERR(goto done));
	cp->add(cp, point);


	/* Register the contour point. */
	if ( _is_mapped(S->contours, cp) ) {
		retn	   = true;
		*status	   = false;
		goto done;
	}


	/* Update the platform measurement. */
	if ( !_extend_measurement(S, cp->get(cp), S->measurement) )
		ERR(goto done);


	/* Add the contour point. */
	if ( !S->contours->add(S->contours, (unsigned char *) &cp, \
			       sizeof(Buffer)) )
		ERR(goto done);
	release_point = false;

	if ( S->sealed ) {
		cp->set_invalid(cp);
		list = S->forensics;
		if ( !event->get_pid(event, &S->discipline_pid) )
			ERR(goto done);
	}
	else {
		++S->size;
		list = S->trajectory;
	}

	if ( !list->add(list, (unsigned char *) &event, \
			sizeof(ExchangeEvent)) )
		ERR(goto done);

	retn  = true;
	added = true;

 done:
	if ( retn ) {
		*status	    = added;
		*discipline = !cp->is_valid(cp);
	}

	WHACK(point);
	if ( release_point )
		WHACK(cp);

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements updating the currently maintained behavioral
 * model with a specific contour point.
 *
 * \param this	A pointer to the object that is being modeled.
 *
 * \param point	An object containing the binary contour point that is
 *		is to be added to the behavioral map.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the the point was registered.  A false value indicates
 *		a failure while a true value indicates the model
 *		was updated.
 */

static _Bool update_map(CO(ISOidentity, this), CO(Buffer, bpoint))

{
	STATE(S);

	_Bool retn = false;

	ContourPoint cp = NULL;


	/* Validate object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bpoint->poisoned(bpoint) )
		ERR(goto done);
	if ( bpoint->size(bpoint) != NAAAIM_IDSIZE )
		ERR(goto done);
	if ( S->sealed )
		ERR(goto done);


	/* Register the binary contour point. */
	INIT(NAAAIM, ContourPoint, cp, ERR(goto done));

	cp->add(cp, bpoint);
	if ( _is_mapped(S->contours, cp) ) {
		retn = true;
		goto done;
	}


	/* Update the platform measurement. */
	if ( !_extend_measurement(S, cp->get(cp), S->measurement) )
		ERR(goto done);


	/* Add the contour point. */
	if ( !S->contours->add(S->contours, (unsigned char *) &cp, \
			       sizeof(ContourPoint)) )
		ERR(goto done);
	retn = true;


 done:
	if ( !retn )
		WHACK(cp);

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
	if ( S->sealed && S->have_aggregate ) {
		retn = true;
		goto done;
	}
	if ( S->have_aggregate )
		ERR(goto done);

	if ( !_extend_measurement(S, bufr->get(bufr), S->measurement) )
		ERR(goto done);
	memcpy(S->domain_aggregate, S->measurement, \
	       sizeof(S->domain_aggregate));

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
 * This method implements adding an AI event to the current behavioral
 * description.
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

static _Bool add_ai_event(CO(ISOidentity, this), CO(String, event))

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);
	if ( event->poisoned(event) )
		ERR(goto done);

	if ( !S->ai_events->add(S->ai_events, (unsigned char *) &event, \
			sizeof(String)) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the AI events which
 * have been injected into the model.  This method is designed to be
 * called repeatedly until the list of AI events is completely traversed.
 * The traversal can be reset by calling the ->rewind_ai_event method.
 *
 * \param this	A pointer to the canister whose AI events are to be
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

static _Bool get_ai_event(CO(ISOidentity, this), String * const event)

{
	STATE(S);

	_Bool retn = true;

	size_t size;

	String *event_ptr,
	       return_event = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Get and verify cursor position. */
	size = S->ai_events->size(S->ai_events) / sizeof(String);
	if ( S->ai_events_cursor >= size ) {
		retn = true;
		goto done;
	}

	event_ptr  = (String *) S->ai_events->get(S->ai_events);
	event_ptr += S->ai_events_cursor;
	return_event = *event_ptr;
	++S->ai_events_cursor;
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
 * This method implements returning the number of AI events in the
 * current behavioral model.
 *
 * \param this	A pointer to the object whose IA event size is to
 *		be returned.
 *
 * \return	The size of the AI events list.
 *
 */

static void ai_rewind_event(CO(ISOidentity, this))

{
	this->state->ai_events_cursor = 0;
	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of AI events in the
 * current behavioral model.
 *
 * \param this	A pointer to the object whose IA event size is to
 *		be returned.
 *
 * \return	The size of the AI events list.
 *
 */

static size_t ai_events_size(CO(ISOidentity, this))

{
	STATE(S);

	return S->ai_events->size(S->ai_events) / sizeof(String);
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

	ContourPoint cp1 = *(ContourPoint *) a1,
		     cp2 = *(ContourPoint *) a2;

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

static _Bool get_state(CO(ISOidentity, this), CO(Buffer, out))

{
	STATE(S);

	_Bool retn = false;

	unsigned char state[NAAAIM_IDSIZE];

	size_t cnt;

	Buffer points = NULL;

	ContourPoint *ep,
		     event;


	/* Sort a copy of the event points. */
	INIT(HurdLib, Buffer, points, ERR(goto done));
	if ( !points->add_Buffer(points, S->contours) )
		ERR(goto done);

	cnt = points->size(points) / sizeof(ContourPoint);
	qsort(points->get(points), cnt, sizeof(ContourPoint), _state_sort);

	ep = (ContourPoint *) points->get(points);
	memcpy(state, S->domain_aggregate, sizeof(state));

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

static _Bool discipline_pid(CO(ISOidentity, this), pid_t * const pid)

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

static _Bool get_event(CO(ISOidentity, this), ExchangeEvent * const event)

{
	STATE(S);

	_Bool retn = true;

	size_t size;

	ExchangeEvent *event_ptr,
		      return_event = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Get and verify cursor position. */
	size = S->trajectory->size(S->trajectory) / sizeof(ExchangeEvent);
	if ( S->trajectory_cursor >= size ) {
		retn = true;
		goto done;
	}

	event_ptr  = (ExchangeEvent *) S->trajectory->get(S->trajectory);
	event_ptr += S->trajectory_cursor;
	return_event = *event_ptr;
	++S->trajectory_cursor;
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

static void rewind_event(CO(ISOidentity, this))

{
	this->state->trajectory_cursor = 0;
	return;
}


/**
 * External public method.
 *
 * This method is an accessor method for retrieving the contour points
 * which comprise the behavior model implemented in an object.  This
 * method is designed to be called repeatedly until the list of events
 * is completely traversed.  The traversal can be reset by calling the
 * ->rewind_contours method.
 *
 * \param this	A pointer to the canister whose contours are to be
 *		retrieved.
 *
 * \param event	The object which the contour will be copied to.
 *
 * \return	A boolean value is used to indicate whether or not
 *		a contour event was returned.  A false value
 *		indicates a failure occurred and a valid conour is
 *		not available.  A true value indicates the contour
 *		object contains a valid value.
 *
 *		The end of the contour list is signified by a NULL
 *		contour object being set.
 */

static _Bool get_contour(CO(ISOidentity, this), ContourPoint * const contour)

{
	STATE(S);

	_Bool retn = true;

	size_t size;

	ContourPoint *contour_ptr,
		     return_contour = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Get and verify cursor position. */
	size = S->contours->size(S->contours) / sizeof(ContourPoint);
	if ( S->contours_cursor >= size ) {
		retn = true;
		goto done;
	}

	contour_ptr  = (ContourPoint *) S->contours->get(S->contours);
	contour_ptr += S->contours_cursor;
	return_contour = *contour_ptr;
	++S->contours_cursor;
	retn = true;

 done:
	if ( !retn )
		S->poisoned = true;
	else
		*contour = return_contour;

	return retn;
}


/**
 * External public method.
 *
 * This method resets the contour retrieval cursor.
 *
 * \param this	A pointer to the canister whose contours are to be
 *		retrieved.
 *
 * \return	No return value is defined.
 */

static void rewind_contours(CO(ISOidentity, this))

{
	this->state->contours_cursor = 0;
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

static size_t contours_size(CO(ISOidentity, this))

{
	STATE(S);

	return S->contours->size(S->contours) / sizeof(Buffer);
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

static _Bool get_forensics(CO(ISOidentity, this), ExchangeEvent * const event)

{
	STATE(S);

	_Bool retn = true;

	size_t size;

	ExchangeEvent *event_ptr,
		      return_event = NULL;


	/* Check object status. */
	if ( S->poisoned )
		goto done;


	/* Get and verify cursor position. */
	size = S->forensics->size(S->forensics) / sizeof(ExchangeEvent);
	if ( S->forensics_cursor >= size ) {
		retn = true;
		goto done;
	}

	event_ptr  = (ExchangeEvent *) S->forensics->get(S->forensics);
	event_ptr += S->forensics_cursor;
	return_event = *event_ptr;
	++S->forensics_cursor;
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

static void rewind_forensics(CO(ISOidentity, this))

{
	this->state->forensics_cursor = 0;
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

static size_t forensics_size(CO(ISOidentity, this))

{
	STATE(S);

	return S->forensics->size(S->forensics) / sizeof(ExchangeEvent);
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

	size_t lp = 1;

	ExchangeEvent event;


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

static void dump_forensics(CO(ISOidentity, this))

{
	STATE(S);

	size_t lp = 1;

	ExchangeEvent event;


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

static void dump_contours(CO(ISOidentity, this))

{
	STATE(S);

	Buffer bufr = NULL;

	ContourPoint contour;


	/* Verify object status. */
	if ( S->poisoned ) {
		fputs("*Poisoned.\n", stdout);
		return;
	}


	/* Traverse and dump the contours. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	rewind_contours(this);
	do {
		if ( !get_contour(this, &contour) ) {
			fputs("Error retrieving event.\n", stdout);
			return;
		}
		if ( contour != NULL ) {
			if ( !bufr->add(bufr, contour->get(contour), \
					NAAAIM_IDSIZE) )
				ERR(goto done);
			bufr->print(bufr);
			bufr->reset(bufr);
		}
	} while ( contour != NULL );


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

static void seal(CO(ISOidentity, this))

{
	this->state->sealed = true;
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
 * This method implements returning the number of points in the
 * behavioral map.
 *
 * \param this	A pointer to the object which is to be destroyed.
 *
 * \return	The size of the behavioral map.
 *
 */

static size_t size(CO(ISOidentity, this))

{
	return this->state->size;
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

	GWHACK(ExchangeEvent, S->forensics);
	WHACK(S->forensics);

	GWHACK(ContourPoint, S->contours);
	WHACK(S->contours);

	GWHACK(String, S->ai_events);
	WHACK(S->ai_events);

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
	INIT(HurdLib, Buffer, this->state->forensics, goto fail);
	INIT(HurdLib, Buffer, this->state->ai_events, goto fail);

	/* Method initialization. */
	this->update	 = update;
	this->update_map = update_map;

	this->set_aggregate   = set_aggregate;

	this->add_ai_event    = add_ai_event;
	this->get_ai_event    = get_ai_event;
	this->ai_events_size  = ai_events_size;
	this->ai_rewind_event = ai_rewind_event;

	this->get_measurement = get_measurement;
	this->get_state	      = get_state;
	this->discipline_pid  = discipline_pid;

	this->get_event	   = get_event;
	this->rewind_event = rewind_event;

	this->get_contour     = get_contour;
	this->rewind_contours = rewind_contours;
	this->contours_size   = contours_size;

	this->get_forensics	= get_forensics;
	this->rewind_forensics	= rewind_forensics;
	this->forensics_size	= forensics_size;

	this->dump_events    = dump_events;
	this->dump_contours  = dump_contours;
	this->dump_forensics = dump_forensics;

	this->seal  = seal;
	this->size  = size;
	this->whack = whack;

	return this;

fail:
	WHACK(this->state->trajectory);
	WHACK(this->state->contours);

	root->whack(root, this, this->state);
	return NULL;
}
