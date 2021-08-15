/** \file
 * This file contains the implementation of the Sancho interpreter.
 * This code runs in a thread that takes TTYduct encapsulated commands
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
#include <string.h>

#include <cmsis_os.h>
#include <rtosal.h>
#include <com_sockets.h>
#include <dc_common.h>
#include <cellular_service_task.h>

#include "HurdLib.h"
#include <Buffer.h>
#include <String.h>
#include <SHA256.h>

#include <sancho-cmd.h>

#include "ExchangeEvent.h"
#include "ContourPoint.h"
#include "ISOidentity.h"
#include "TTYduct.h"
#include "Duct.h"

#include "sancho.h"


/**
 * Flag variable to indicate that cellular notification is available.
 */
static _Bool Cellular_Enabled = false;

/* Communications object to be used by all functions. */
TTYduct Host;

/* Flag to specifier interpreter error. */
static _Bool Have_Error;

/* Static declarations for interpreter thread. */
static osSemaphoreId interpreter_semaphore = 0;
static osThreadId interpreter_id;


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

static void send_ok(CO(TTYduct, duct), CO(Buffer, bufr))

{
	static char *ok = "OK";


	bufr->reset(bufr);

	if ( !bufr->add(bufr, (unsigned char *) ok, strlen(ok) + 1) )
		return;
	duct->send_Buffer(duct, bufr);

	bufr->reset(bufr);

	return;
}


static _Bool add_state(ISOidentity model, Buffer cp)

{
	_Bool retn = false;

	char *p;

	Buffer bufr = NULL;


	/* Parse event. */
	p = (char *) cp->get(cp);
	if ( (p = index(p, ' ')) == NULL )
		ERR(goto done);

	++p;
	if ( strlen(p) != 64 )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add_hexstring(bufr, p) )
		ERR(goto done);

	if ( !model->update_map(model, bufr) )
		ERR(goto done);

	retn = true;

 done:
	WHACK(bufr);

	return retn;
}


/**
 * Private function.
 *
 * This function implements the transmission a security event that is
 * invoking discipline of the system being supervised.
 *
 * \param event		The object containing the representation of
 *			the event.
 *
 * \return		No return value is defined.
 */

static void _send_event(CO(String, event))

{
	Buffer bufr = NULL;

	Duct duct = NULL;

	if ( !Cellular_Enabled )
		return;

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (unsigned char *) event->get(event), \
			event->size(event) + 1) )
		goto done;

	INIT(NAAAIM, Duct, duct, ERR(goto done));
	if ( !duct->init_client(duct) )
		goto done;

	if ( !duct->init_port(duct, "76.10.64.91", 10902) )
		goto done;

	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


 done:
	WHACK(bufr);
	WHACK(duct);

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

static void add_event(CO(TTYduct, duct), CO(ISOidentity, model), \
		      CO(Buffer, bufr))

{
	char *p,
	     msg[80];

	_Bool updated,
	      discipline;

	int msg_size;

	pid_t pid;

	String update = NULL;

	ExchangeEvent event = NULL;


	/* Parse event. */
	p = (char *) bufr->get(bufr);
	if ( (p = index(p, ' ')) == NULL )
		ERR(goto done);
	++p;

	INIT(HurdLib, String, update, ERR(goto done));
	if ( !update->add(update, p) )
		ERR(goto done);

	INIT(NAAAIM, ExchangeEvent, event, ERR(goto done));
	if ( !event->parse(event, update) )
		ERR(goto done);
	if ( !event->measure(event) )
		ERR(goto done);
	if ( !model->update(model, event, &updated, &discipline) )
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
		if ( updated )
			_send_event(update);
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

static void add_aggregate(CO(TTYduct, duct), CO(ISOidentity, model), \
			  CO(Buffer, bufr))

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

static void add_security(CO(TTYduct, duct), CO(ISOidentity, model), \
			 CO(Buffer, bufr))

{
	String event = NULL;


	INIT(HurdLib, String, event, ERR(goto done));
	event->add(event, (char *) bufr->get(bufr));
	if ( model->add_ai_event(model, event) )
		send_ok(duct, bufr);


 done:

	return;
}


/**
 * Private function.
 *
 * This function implements the output of the current behavior identities.
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

static void send_contours(CO(TTYduct, duct), CO(ISOidentity, model), \
			  CO(Buffer, bufr))

{
	uint8_t *p,
		 pi;

	char point[IDSIZE * 2 + 1];

	size_t lp,
	       cnt = 0;

	ContourPoint cp = NULL;


	/*
	 * Compute the number of elements in the list and send it to
	 * the client.
	 */
	cnt = model->contours_size(model);


	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


	/* Send each trajectory point. */
	model->rewind_contours(model);

	for (lp= 0; lp < cnt; ++lp ) {
		if ( !model->get_contour(model, &cp) )
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
 * This function implements the output of the current execution
 * trajectory of the model
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

static void send_trajectory(CO(TTYduct, duct), CO(ISOidentity, model), \
			    CO(Buffer, bufr))

{
	size_t lp,
	       cnt = 0;

	ExchangeEvent event;

	String es = NULL;


	/* Return the number of trajectory items. */
	cnt = model->size(model);

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

static void send_forensics(CO(TTYduct, duct), CO(ISOidentity, model), \
			   CO(Buffer, bufr))

{
	size_t lp,
	       cnt = 0;

	ExchangeEvent event;

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

static void send_events(CO(TTYduct, duct), CO(ISOidentity, model), \
			CO(Buffer, bufr))

{
	size_t lp,
	       cnt = 0;

	String event = NULL;


	/* Get the number of elements in the security list. */
	cnt = model->ai_events_size(model);

	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) &cnt, sizeof(cnt));
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);


	/* Send each event. */
	model->ai_rewind_event(model);

	for (lp= 0; lp < cnt; ++lp) {
		if ( !model->get_ai_event(model, &event) )
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


static void enable_cellular(CO(TTYduct, duct), CO(Buffer, bufr))

{
	static char *ok = "FAILED";

	unsigned int seconds = 30;

	CST_autom_state_t status;


	cellular_start();

	while ( seconds-- > 0 ) {
		status = CST_get_state();
		if ( status == CST_MODEM_DATA_READY_STATE ) {
			Cellular_Enabled = true;
			send_ok(duct, bufr);
			return;

		}
		osDelay(1000);
	}

	bufr->reset(bufr);
	if ( !bufr->add(bufr, (unsigned char *) ok, strlen(ok) + 1) )
		return;

	duct->send_Buffer(duct, bufr);
	bufr->reset(bufr);

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
 * \return	No return value is defined.
 */

static void interpreter(const void *arg)

{
	Buffer bufr = NULL;

	TTYduct duct = NULL;

	ISOidentity model = NULL;


	INIT(HurdLib, Buffer, bufr, (printf("init error.\n")));
	INIT(NAAAIM, TTYduct, duct, (printf("init error.\n")));

	duct->init_device(duct, NULL);

	Host = duct;

	INIT(NAAAIM, ISOidentity, model, (printf("Model init error.\n")));

	while ( true ) {
		if ( !duct->receive_Buffer(duct, bufr) ) {
			bufr->reset(bufr);
			continue;
		}

		switch ( get_command(bufr) ) {
			case sancho_state:
				if ( add_state(model, bufr) )
					send_ok(duct, bufr);
				break;

			case exchange_event:
				add_event(Host, model, bufr);
				break;

			case aggregate_event:
				add_aggregate(Host, model, bufr);
				break;

			case seal_event:
				model->seal(model);
				send_ok(Host, bufr);
				break;

			case ai_event:
				add_security(duct, model, bufr);
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

			case show_forensics:
				send_forensics(duct, model, bufr);
				break;

			case show_contours:
				send_contours(duct, model, bufr);
				break;

			case show_events:
				send_events(duct, model, bufr);
				break;

			case enable_cell:
				enable_cellular(duct, bufr);
				break;

			case sancho_reset:
				NVIC_SystemReset();
				break;
		}

		bufr->reset(bufr);
		Have_Error = false;
	}

	return;
}


/**
 * External function call.
 *
 * This function implements the initialization of the thread that
 * will run the interpreter function.
 *
 * \return	A pointer to the initialized Actor.  A null value
 *		indicates an error was encountered in object generation.
 */

_Bool interpreter_init(void)

{
	_Bool retn = false;


	interpreter_semaphore = rtosalSemaphoreNew(NULL, 1);
	rtosalSemaphoreAcquire(interpreter_semaphore, RTOSAL_WAIT_FOREVER);


	interpreter_id = rtosalThreadNew((unsigned char *) "interpreter", \
					 interpreter, osPriorityNormal,	  \
					 600, NULL);
	if ( interpreter_id == NULL )
		ERR(goto done);
	retn = true;

 done:
	return retn;
}


void Error(const char *file, const char *function, int line)

{
	char bufr[80];

	Buffer msg = NULL;


	if ( Have_Error )
		return;

	memset(bufr, '\0', sizeof(bufr));
	snprintf(bufr, sizeof(bufr), "T[%s,%s,%d]: Error location.", file, \
		 function, line);

	INIT(HurdLib, Buffer, msg, return);
	msg->add(msg, (unsigned char *) bufr, strlen(bufr) + 1);
	Host->send_Buffer(Host, msg);

	Have_Error = true;
	WHACK(msg);
	return;


}
