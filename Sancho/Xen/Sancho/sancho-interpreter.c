/** \file
 * This file contains the implementation of the Sancho interpreter.
 * This code runs in a thread that takes XENduct encapsulated commands
 * from the Quixote instance and executes them.
 */

/**************************************************************************
 * (C)Copyright 2021, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

/* Module definitions. */
#define IDSIZE 32


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "HurdLib.h"
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>
#include <NAAAIM.h>

#include <sancho-cmd.h>

#include "SecurityEvent.h"
#include "SecurityPoint.h"
#include "TSEM.h"
#include "XENduct.h"

#include "sancho.h"


/* Communications object to be used by all functions. */
XENduct Host;

/* Flag to specifier interpreter error. */
static _Bool Have_Error;


/**
 * Private function.
 *
 * This function encapsulates the sending of a response indicating
 * that the previously executed operation has succeeded.
 *
 * \param duct		The object describing the communications duct
 *			over which the response is to be sent.
 *
 * \param bufr		A Buffer object that will be used to send
 *			the message.  This object will be reset upon
 *			return.
 *
 * \return
 */

static void send_ok(CO(XENduct, duct), CO(Buffer, bufr))

{
	static char *ok = "OK";


	bufr->reset(bufr);

	if ( !bufr->add(bufr, (unsigned char *) ok, strlen(ok) + 1) )
		return;
	duct->send_Buffer(duct, bufr);

	bufr->reset(bufr);

	return;
}


/**
 * Private function.
 *
 * This function implements the updating of the platfrom behavior model
 * with an information exchange event.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance that is to be updated.
 *
 * \param bufr		A Buffer object containing the exchange event
 *			description.
 *
 * \return		No return value is defined.
 */

static void add_event(CO(XENduct, duct), CO(TSEM, model), CO(Buffer, bufr))

{
	char *p,
	     msg[80];

	_Bool updated,
	      discipline,
	      sealed;

	int msg_size;

	pid_t pid;

	String update = NULL;

	SecurityEvent event = NULL;


	/* Parse event. */
	p = (char *) bufr->get(bufr);
	if ( (p = index(p, ' ')) == NULL )
		ERR(goto done);
	++p;

	INIT(HurdLib, String, update, ERR(goto done));
	if ( !update->add(update, p) )
		ERR(goto done);

	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
	if ( !event->parse(event, update) )
		ERR(goto done);
	if ( !model->update(model, event, &updated, &discipline, &sealed) )
		ERR(goto done);


	/* Send response. */
	if ( discipline ) {
		memset(msg, '\0', sizeof(msg));
		model->discipline_pid(model, &pid);
		msg_size = snprintf(msg, sizeof(msg) - 1, "DISCIPLINE %d", \
				    pid);
		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) msg, msg_size + 1);
		duct->send_Buffer(duct, bufr);
	} else {
		memset(msg, '\0', sizeof(msg));
		event->get_pid(event, &pid);
		msg_size = snprintf(msg, sizeof(msg) - 1, "RELEASE %d", \
				    pid);
		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) msg, msg_size + 1);
		duct->send_Buffer(duct, bufr);
	}


 done:
	WHACK(update);
	if ( !updated )
		WHACK(event);

	return;
}


/**
 * Private function.
 *
 * This function implements the addition of a hardware platform aggregate
 * event to the specified behavior model.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance that is to be updated.
 *
 * \param bufr		A Buffer object containing the aggregate value
 *			to be added.
 *
 * \return		No return value is defined.
 */

static void add_aggregate(CO(XENduct, duct), CO(TSEM, model), CO(Buffer, bufr))

{
	char *p;

	Buffer aggregate = NULL;


	p = (char *) bufr->get(bufr);
	if ( (p = index(p, ' ')) == NULL )
		ERR(goto done);

	++p;
	if ( strlen(p) != 64 )
		ERR(goto done);

	INIT(HurdLib, Buffer, aggregate, ERR(goto done));
	if ( !aggregate->add_hexstring(aggregate, p) )
		ERR(goto done);

	if ( model->set_aggregate(model, aggregate) )
		send_ok(duct, bufr);


 done:
	WHACK(aggregate);

	return;
}


/**
 * Private function.
 *
 * This function implements the addition of a security event to the
 * specified behavior model.
 *
 * \Param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance that is to be updated.
 *
 * \param bufr		A Buffer object containing the security event
 *			to be added.
 *
 * \return		No return value is defined.
 */

static void add_security(CO(XENduct, duct), CO(TSEM, model), CO(Buffer, bufr))

{
	String event = NULL;


	INIT(HurdLib, String, event, ERR(goto done));
	event->add(event, (char *) bufr->get(bufr));
	if ( model->add_TSEM_event(model, event) )
		send_ok(duct, bufr);


 done:

	return;
}


/**
 * Private function.
 *
 * This function implements the loading of entries into a security
 * model.
 *
 * \Param duct		The object used to implement communications
 *			with the Quixote instance.
 *
 * \param model		The model instance that is to be updated.
 *
 * \param bufr		A Buffer object containing the entry to be
 *			loaded into the security model.
 *
 * \return		No return value is defined.
 */

static void do_load(CO(XENduct, duct), CO(TSEM, model), CO(Buffer, bufr))

{
	char *p,
	     *load_start;

	const static char error[] = "ERROR";

	String entry = NULL;


	load_start = (char *) bufr->get(bufr);
	if ( (p = strchr(load_start, ' ')) == NULL )
		goto done;
	++p;

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, p) )
		goto done;

	if ( !model->load(model, entry) )
		goto done;

	send_ok(duct, bufr);
	return;


 done:
	bufr->reset(bufr);
	if ( !bufr->add(bufr, (unsigned char *) error, sizeof(error)) )
		return;
	duct->send_Buffer(duct, bufr);
}


/**
 * Private function.
 *
 * This function implements the output of the current execution
 * trajectory of the model.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance whose trajectory is to
 *			be displayed.
 *
 * \param bufr		A Buffer object to be used for sending
 *			the trajectory elements.
 *
 * \return		No return value is defined.
 */

static void send_trajectory(CO(XENduct, duct), CO(TSEM, model), \
			    CO(Buffer, bufr))

{
	size_t lp,
	       cnt = 0;

	SecurityEvent event;

	String es = NULL;


	/* Return the number of trajectory items. */
	cnt = model->trajectory_size(model);

	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


	/* Send each trajectory point. */
	INIT(HurdLib, String, es, ERR(goto done));

	model->rewind_event(model);
	for (lp= 0; lp < cnt; ++lp ) {
		if ( !model->get_event(model, &event) )
			ERR(goto done);
		if ( event == NULL )
			continue;
		if ( !event->format(event, es) )
			ERR(goto done);

		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) es->get(es), \
			  es->size(es) + 1);
		if ( !duct->send_Buffer(duct, bufr) )
			ERR(goto done);
		es->reset(es);
	}


 done:
	WHACK(es);

	return;
}


/**
 * Private function.
 *
 * This function implements the output of the current set of valid
 * security state coefficients in the model.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance whose contours are to be
 *			displayed.
 *
 * \param bufr		A Buffer object to be used for displaying
 *			the behavioral identities.
 *
 * \return		No return value is defined.
 */

static void send_trajectory_coefficients(CO(XENduct, duct), CO(TSEM, model), \
					 CO(Buffer, bufr))

{
	uint8_t *p,
		 pi;

	char point[IDSIZE * 2 + 1];

	size_t lp,
	       cnt = 0;

	SecurityPoint cp = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	cnt = model->points_size(model);


	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


	/* Send each trajectory point. */
	model->rewind_points(model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !model->get_point(model, &cp) )
			ERR(goto done);
		if ( cp == NULL )
			continue;

		memset(point, '\0', sizeof(point));
		p = cp->get(cp);
		for (pi= 0; pi < IDSIZE; ++pi)
			snprintf(&point[pi*2], 3, "%02x", *p++);

		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) point, sizeof(point));
		if ( !duct->send_Buffer(duct, bufr) )
			ERR(goto done);
	}


 done:
	return;
}


/**
 * Private function.
 *
 * This function implements the output of the occupancy counts of
 * the security state coefficients.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance whose contours are to be
 *			displayed.
 *
 * \param bufr		A Buffer object to be used for displaying
 *			the behavioral identities.
 *
 * \return		No return value is defined.
 */

static void send_trajectory_counts(CO(XENduct, duct), CO(TSEM, model),
				   CO(Buffer, cmdbufr))

{
	char bufr[21];

	size_t lp,
	       cnt = 0;

	SecurityPoint cp = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	cnt = model->points_size(model);


	cmdbufr->reset(cmdbufr);
	cmdbufr->add(cmdbufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !duct->send_Buffer(duct, cmdbufr) )
		ERR(goto done);


	/* Send each trajectory point. */
	model->rewind_points(model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !model->get_point(model, &cp) )
			ERR(goto done);
		if ( cp == NULL )
			continue;
		if ( !cp->is_valid )
			continue;

		snprintf(bufr, sizeof(bufr), "%lu", cp->get_count(cp));

		cmdbufr->reset(cmdbufr);
		cmdbufr->add(cmdbufr, (unsigned char *) bufr, sizeof(bufr));
		if ( !duct->send_Buffer(duct, cmdbufr) )
			ERR(goto done);
	}


 done:
	return;
}


/**
 * Private function.
 *
 * This function implements the output of the current forensics log
 * for the specified model.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance whose forensics are to
 *			be displayed.
 *
 * \param bufr		A Buffer object to be used for sending
 *			the forensics elements..
 *
 * \return		No return value is defined.
 */

static void send_forensics(CO(XENduct, duct), CO(TSEM, model), \
			   CO(Buffer, bufr))

{
	size_t lp,
	       cnt = 0;

	SecurityEvent event;

	String es = NULL;


	/* Return the number of trajectory items. */
	cnt = model->forensics_size(model);

	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


	/* Send each trajectory point. */
	INIT(HurdLib, String, es, ERR(goto done));

	model->rewind_forensics(model);
	for (lp= 0; lp < cnt; ++lp ) {
		if ( !model->get_forensics(model, &event) )
			ERR(goto done);
		if ( event == NULL )
			continue;
		if ( !event->format(event, es) )
			ERR(goto done);

		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) es->get(es), \
			  es->size(es) + 1);
		if ( !duct->send_Buffer(duct, bufr) )
			ERR(goto done);
		es->reset(es);
	}


 done:
	WHACK(es);

	return;
}


/**
 * Private function.
 *
 * This function implements the output of the current security event log
 * for the specified model.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \param model		The model instance whose forensics are to
 *			be displayed.
 *
 * \param bufr		A Buffer object to be used for sending
 *			the events.
 *
 * \return		No return value is defined.
 */

static void send_events(CO(XENduct, duct), CO(TSEM, model), CO(Buffer, bufr))

{
	size_t lp,
	       cnt = 0;

	String event = NULL;


	/* Get the number of elements in the security list. */
	cnt = model->TSEM_events_size(model);

	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


	/* Send each event. */
	model->TSEM_rewind_event(model);

	for (lp= 0; lp < cnt; ++lp) {
		if ( !model->get_TSEM_event(model, &event) )
				ERR(goto done);
		if ( event == NULL )
				continue;

		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) event->get(event), \
			  event->size(event));
		if ( !duct->send_Buffer(duct, bufr) )
			ERR(goto done);
	}


done:
	return;
}


static int get_command(CO(Buffer, bufr))

{
	char *bp;

	struct sancho_cmd_definition *cp;


	/* Locate the event type. */
	bp = (char *) bufr->get(bufr);

	for (cp= Sancho_cmd_list; cp->syntax != NULL; ++cp) {
		if ( strncmp(cp->syntax, bp, strlen(cp->syntax)) == 0 )
			break;
	}

	return cp->command;
}


/**
 * External function call.
 *
 * This function implements the Sancho command interpreter.
 *
 * \param duct		The object used to implement communications
 *			with the host.
 *
 * \return	No return value is defined.
 */

extern void sancho_interpreter(const XENduct duct)

{
	_Bool connected = true;

	Buffer bufr = NULL;

	TSEM model = NULL;


	Host = duct;

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, TSEM, model, ERR(goto done));

	while ( connected ) {
		if ( !duct->receive_Buffer(duct, bufr) )
			ERR(goto done);

		if ( duct->eof(duct) )
			goto done;

		switch ( get_command(bufr) ) {
			case export_event:
				add_event(Host, model, bufr);
				break;

			case aggregate_event:
				add_aggregate(Host, model, bufr);
				break;

			case seal_event:
				model->seal(model);
				send_ok(Host, bufr);
				break;

			case log_event:
				add_security(duct, model, bufr);
				break;

			case sancho_load:
				do_load(duct, model, bufr);
				break;

			case show_measurement:
				bufr->reset(bufr);
				model->get_measurement(model, bufr);
				duct->send_Buffer(duct, bufr);
				break;

			case show_state:
				bufr->reset(bufr);
				model->get_state(model, bufr);
				duct->send_Buffer(duct, bufr);
				break;

			case show_trajectory:
				send_trajectory(duct, model, bufr);
				break;

			case show_coefficients:
				send_trajectory_coefficients(duct, model, \
							     bufr);
				break;

			case show_counts:
				send_trajectory_counts(duct, model, bufr);
				break;

			case show_forensics:
				send_forensics(duct, model, bufr);
				break;

			case show_events:
				send_events(duct, model, bufr);
				break;

			case enable_cell:
				send_ok(Host, bufr);
				break;

			case sancho_reset:
				connected = false;
				break;
		}

		bufr->reset(bufr);
		Have_Error = false;
	}


 done:
	WHACK(bufr);
	WHACK(model);

	return;
}
