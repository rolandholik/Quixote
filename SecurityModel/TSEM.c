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
#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"


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

	/* Execution trajectory list. */
	Gaggle trajectory;

	/* Security state point list. */
	Gaggle points;

	/* Forensics trajectory list. */
	Gaggle forensics;

	/* TE events list. */
	Gaggle TE_events;
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
	S->sealed	  = false;

	S->discipline_pid = 0;

	memset(S->hostid, '\0', sizeof(S->hostid));
	memset(S->domain_aggregate, '\0', sizeof(S->domain_aggregate));
	memset(S->measurement, '\0', sizeof(S->measurement));

	S->trajectory	= NULL;
	S->points	= NULL;
	S->forensics	= NULL;
	S->TE_events	= NULL;

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
	map->reset(map);

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

static _Bool update(CO(TSEM, this), CO(SecurityEvent, event), _Bool *status, \
		    _Bool *discipline)

{
	STATE(S);

	_Bool retn	    = false,
	      added	    = false,
	      release_point = true;

	Buffer point = NULL;

	Gaggle list;

	SecurityPoint cp = NULL;


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
	 * the security state point that will be processed.
	 */
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

static _Bool update_map(CO(TSEM, this), CO(Buffer, bpoint))

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

static _Bool add_TE_event(CO(TSEM, this), CO(String, event))

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
 * This method is an accessor method for retrieving the TE events which
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

static _Bool get_TE_event(CO(TSEM, this), String * const event)

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

static void TE_rewind_event(CO(TSEM, this))

{
	STATE(S);

	S->TE_events->reset(S->TE_events);
	return;
}


/**
 * External public method.
 *
 * This method implements returning the number of TE events in the
 * current security model
 *
 * \param this	A pointer to the object whose event size is to
 *		be returned.
 *
 * \return	The size of the events list.
 *
 */

static size_t TE_events_size(CO(TSEM, this))

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
	S->points->reset(S->points);

	while ( cnt-- ) {
		p = S->points->get(S->points);
		if ( !points->add(points, p, sizeof(void *)) )
			ERR(goto done);
	}


	/* Sort the points. */
	cnt = S->points->size(S->points);
	qsort(points->get(points), cnt, sizeof(SecurityPoint), _state_sort);

	ep = (SecurityPoint *) points->get(points);
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

	S->trajectory->reset(S->trajectory);
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

	S->points->reset(S->points);
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

	S->forensics->reset(S->forensics);
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


	GWHACK(S->trajectory, SecurityEvent);
	WHACK(S->trajectory);

	GWHACK(S->forensics, SecurityEvent);
	WHACK(S->forensics);

	GWHACK(S->points, SecurityPoint);
	WHACK(S->points);

	GWHACK(S->TE_events, String);
	WHACK(S->TE_events);

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
	INIT(HurdLib, Gaggle, this->state->trajectory, goto fail);
	INIT(HurdLib, Gaggle, this->state->points, goto fail);
	INIT(HurdLib, Gaggle, this->state->forensics, goto fail);
	INIT(HurdLib, Gaggle, this->state->TE_events, goto fail);

	/* Method initialization. */
	this->update	 = update;
	this->update_map = update_map;

	this->set_aggregate   = set_aggregate;

	this->add_TE_event    = add_TE_event;
	this->get_TE_event    = get_TE_event;
	this->TE_events_size  = TE_events_size;
	this->TE_rewind_event = TE_rewind_event;

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
	WHACK(this->state->trajectory);
	WHACK(this->state->points);

	root->whack(root, this, this->state);
	return NULL;
}