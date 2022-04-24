/** \file
 * This file provides the implementation of an object that provides
 * packet based communications between Xen domains using a shared
 * memory page and an event channel.  This is a simple write and
 * read response interface and thus concurrent writes and asynchronous
 * interactions do not need to be supported.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include <os.h>
#include <xenbus.h>
#include <events.h>
#include <shutdown.h>
#include <mini-os/lib.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "XENduct.h"

/* State extraction macro. */
#define STATE(var) CO(XENduct_State, var) = this->state

/* Maximum receive buffer size: 4K-sizeof(uint32_t) */
#define MAX_RECEIVE_SIZE 4092


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_XENduct_OBJID)
#error Object identifier not defined.
#endif


/** A flag to indicate that a duct event has occurred. */
static _Bool Have_event = false;

/** LocalDuct private state information. */
struct NAAAIM_XENduct_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* End of transmission flag. */
	_Bool eof;

	/* Remove domain identity. */
	unsigned int remote_id;

	/* Xen event queue used to monitor for xenstore events. */
	xenbus_event_queue events;

	/* Grant mappings. */
	struct gntmap map;

	/* Shared page address. */
	uint8_t *grant_page;

	/* Shared buffer. */
	uint8_t *bufr;

	/* Local event channel port. */
	evtchn_port_t ev_local;

	/* Remote event channel port. */
	evtchn_port_t ev_remote;
};


/* Replacements for byte swapping functions. */
static inline uint32_t htonl(uint32_t value)

{
	return value >> 24 | (value >> 8 & 0xff00) | \
		(value << 8 & 0xff0000) | value << 24;
}

static inline uint32_t ntohl(uint32_t value)

{
	return value >> 24 | (value >> 8 & 0xff00) | \
		(value << 8 & 0xff0000) | value << 24;
}


/**
 * Internal private function.
 *
 * This method is responsible for handling event channel 'interrupts'.
 *
 * \param vp	The port event number that was triggered.
 *
 * \param regs	A pointer to the structure containing the register
 *		state at the time of the event.
 *
 * \param page	A pointer to the page that is shared between the domains.
 */

void _event_handler(evtchn_port_t vp, struct pt_regs *regs, void *page)

{
	Have_event = true;
	return;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the QUIXOTE_LocalDuct_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(XENduct_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_XENduct_OBJID;

	S->poisoned = false;
	S->eof	    = false;

	S->remote_id = 0;
	S->events    = NULL;

	memset(&S->map, '\0', sizeof(struct gntmap));
	S->grant_page = NULL;

	S->ev_local  = 0;
	S->ev_remote = 0;

	return;
}


/**
 * External public method.
 *
 * This method initializes a XENduct connection.  This simply consists
 * of creating the events queue entry that will be used to monitor
 * for xenstore based connections.
 *
 * \param this	The communications object which is to be initialized.
 *
 * \param path	A null-terminated string containing the path that is
 *		to be monitored for connection requests from a Quixote
 *		instance.
 *
 * \return	If the device is successfully initialized a boolean
 *		true value is returned.  If initialization fails a
 *		false value is returned and the object is poisoned.
 */

static _Bool init_device(CO(XENduct, this), CO(char *, path))

{
	STATE(S);

	_Bool retn = false;

	char *err,
	     **connect;


	/* Setup a watch for the node. */
	if ( (err = xenbus_watch_path_token(XBT_NIL, path, path, &S->events)) != NULL ) {
		free(err);
		ERR(goto done);
	}

	connect = xenbus_wait_for_watch_return(&S->events);
	if ( strcmp(path, *connect) != 0 )
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
 * This method implements accepting a connection from a quixote client.
 * port.  It does so by monitoring the xenstore connection path for
 * the grant reference and event channel values.
 *
 * \param this	The communications object that is to accept a connection.
 *
 * \return	This call blocks until a connection occurs.  If there
 *		is an error in the connection setup a false value is
 *		returned.  If the connection is setup properly a true
 *		value is returned.
 */

static _Bool accept_connection(CO(XENduct, this))

{
	STATE(S);

	_Bool retn    = false,
	      waiting = true;

	char *err,
	     **connect,
	     *refstr = NULL;

	unsigned int remote_id;

	grant_ref_t grant;


	/* Wait for a connection .*/
	while ( waiting ) {
		connect = xenbus_wait_for_watch_return(&S->events);
		if ( strstr(*connect, "connect") != NULL )
			waiting = false;
		free(connect);
	}


	/* Process grant reference connection. */
	connect = xenbus_wait_for_watch_return(&S->events);
	if ( sscanf(*connect, "backend/SanchoXen/%u/grant-ref", \
		    &remote_id) != 1 ) {
		free(connect);
		ERR(goto done);
	}

	if ( (err = xenbus_read(XBT_NIL, *connect, &refstr)) != NULL ) {
		free(err);
		free(connect);
		ERR(goto done);
	}
	free(connect);

	grant = (unsigned int) strtol(refstr, NULL, 0);
	if ( errno == ERANGE )
		ERR(goto done);
	if ( (S->grant_page = gntmap_map_grant_refs(&S->map, 1, &remote_id,  \
						    0, &grant,		     \
						    PROT_READ | PROT_WRITE)) \
	     == NULL )
		ERR(goto done);

	memset(S->grant_page, '\0', 4096);
	S->bufr = S->grant_page + sizeof(uint32_t);


	/* Obtain event channel. */
        connect = xenbus_wait_for_watch_return(&S->events);
	if ( sscanf(*connect, "backend/SanchoXen/%u/event-channel", \
		    &remote_id) != 1 ) {
		free(connect);
		ERR(goto done);
	}

	if ( (err = xenbus_read(XBT_NIL, *connect, &refstr)) != NULL ) {
		free(err);
		free(connect);
		ERR(goto done);
	}
	free(connect);

	S->ev_remote = (unsigned int) strtol(refstr, NULL, 0);
	if ( errno == ERANGE)
		ERR(goto done);

	if ( evtchn_bind_interdomain(remote_id, S->ev_remote, _event_handler, \
				     S->grant_page, &S->ev_local) != 0 )
		ERR(goto done);

	unmask_evtchn(S->ev_local);
	retn = true;


 done:

	return retn;
}


/**
 * External public method.
 *
 * This method implements sending the contents of a specified Buffer object
 * over the connection represented by the callingn object.
 *
 * \param this	The LocalDuct object over which the Buffer is to be sent.
 *
 * \return	A boolean value is used to indicate whether or the
 *		write was successful.  A true value indicates the
 *		transmission was successful.
 */

static _Bool send_Buffer(CO(XENduct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	uint32_t size = htonl(bf->size(bf));


	/* Verify arguments. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf))
		ERR(goto done);
	if ( bf->size(bf) > MAX_RECEIVE_SIZE )
		ERR(goto done);


	/* Load buffer into shared page area. */
	memcpy(S->bufr, bf->get(bf), bf->size(bf));
	*(uint32_t *) S->grant_page = size;

	notify_remote_via_evtchn(S->ev_local);

	Have_event = false;
	while ( !Have_event )
		continue;

	retn	   = true;
	Have_event = false;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements loading the specified number of bytes into
 * the provided Buffer object.
 *
 * \param this	The LocalDuct object from which data is to be read.
 *
 * \return	A boolean value is used to indicate whether or the
 *		read was successful.  A true value indicates the receive
 *		was successful.
 */

static _Bool receive_Buffer(CO(XENduct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	uint32_t rsize;


	/* Verify arguments. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf) )
		ERR(goto done);


	/* Wait for an event. */
	while ( !Have_event )
		msleep(5);

	rsize = *(uint32_t *) S->grant_page;


	/*
	 * Get the size of the buffer to be received and convert the
	 * network byte order value to a host integer. If more then
	 * the object specified amount is specified set the errno
	 * variable to be a negative value so it can be distinguished
	 * from a standard error number.
	 */
	rsize = ntohl(rsize);
	if ( rsize == 0xffffffff ) {
		retn   = true;
		S->eof = true;
		notify_remote_via_evtchn(S->ev_local);
		goto done;
	}
	if ( rsize > MAX_RECEIVE_SIZE )
		ERR(goto done);


	/* Load the received data into a Buffer object. */
	if ( !bf->add(bf, S->bufr, rsize) )
		ERR(goto done);

	memset(S->grant_page, '\0', 4096);
	retn	   = true;


 done:
	Have_event = false;

	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements an accessor for determining whether or not
 * an end-of-file event has been detected.
 *
 * \param this	A pointer to the object that is to be tested.
 */

static _Bool eof(CO(XENduct, this))

{
	STATE(S);

	return S->eof;
}


/**
 * External public method.
 *
 * This method implements resetting an object so that it can
 * accept another connection from a domain
 *
 * \param this	A pointer to the object that is to be reset.
 */

static void reset(CO(XENduct, this))

{
	STATE(S);


	/* Release shared page. */
	if ( S->grant_page != NULL )
		gntmap_munmap(&S->map, (long unsigned int) S->grant_page, 1);


	/* Release event channel resources. */
	if ( S->ev_local > 0 ) {
		mask_evtchn(S->ev_local);
		unbind_evtchn(S->ev_local);
	}


	/* Initialize object state. */
	S->poisoned = false;
	S->eof	    = false;

	S->remote_id = 0;

	memset(&S->map, '\0', sizeof(struct gntmap));
	S->grant_page = NULL;

	S->ev_local  = 0;
	S->ev_remote = 0;


	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a LocalDuct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(XENduct, this))

{
	STATE(S);


	/* Release shared mapping and event channel. */
	this->reset(this);


	/* Shutdown xenstore watch. */
	xenbus_unwatch_path_token(XBT_NIL, "backend/SanchoXen", \
				  "backend/SanchoXen");


	/* Destroy object. */
	S->root->whack(S->root, this, S);


	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a LocalDuct object.
 *
 * \return	A pointer to the initialized LocalDuct.  A null value
 *		indicates an error was encountered in object generation.
 */

extern XENduct NAAAIM_XENduct_Init(void)

{
	Origin root;

	XENduct this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_XENduct);
	retn.state_size   = sizeof(struct NAAAIM_XENduct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_XENduct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init_device	= init_device;
	this->accept_connection	= accept_connection;

	this->send_Buffer	= send_Buffer;
	this->receive_Buffer	= receive_Buffer;

	this->eof		= eof;
	this->reset		= reset;
	this->whack		= whack;

	return this;
}
