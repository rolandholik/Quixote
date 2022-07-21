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
#include <arpa/inet.h>

#include <xenstore.h>
#include <xengnttab.h>
#include <xenevtchn.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "XENduct.h"

/* Memory barrier primitive. */
#define xen_mb() asm volatile ( "lock addl $0, -32(%%rsp)" ::: "memory" )


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

	/* Handle for communicating with xenstore. */
	struct xs_handle *xh;

	/* Domain id. */
	char *domid;

	/* Remote domain id. */
	unsigned int remote;

	/* Handle for communicating with page granting mechanism. */
	struct xengntdev_handle *gh;

	/* Shared page address. */
	uint8_t *gp;

	/* Status word. */
	uint8_t *sp;

	/* Shared buffer. */
	uint8_t *bufr;

	/* Event channel handle. */
	xenevtchn_handle *evh;

	/* Event channel port. */
	xenevtchn_port_or_error_t evp;

	/* Remote event channel port. */
	evtchn_port_t ev_remote;
};


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

	S->xh	 = NULL;

	S->domid  = NULL;
	S->remote = 0;

	S->gh = NULL;
	S->gp = NULL;
	S->sp = NULL;

	S->evp	     = 0;
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

	char xspath[80],
	     xsvalue[80];

	unsigned int length;

	uint32_t gref;


	/* Verify arguments. */
	if ( S->poisoned )
		ERR(goto done);
	if ( path == NULL )
		ERR(goto done);


	/* Convert domain id to a numeric value. */
	S->remote = (unsigned int) strtol(path, NULL, 0);
	if ( errno == ERANGE)
		ERR(goto done);

	if ( (S->xh = xs_open(0)) == NULL )
		ERR(goto done);

	if ( (S->domid = xs_read(S->xh, XBT_NULL, "domid", &length)) == NULL )
		ERR(goto done);


	/* Initiate connection. */
	if ( snprintf(xspath, sizeof(xspath),			       \
		      "/local/domain/%s/backend/SanchoXen/%s/connect", \
		      path, S->domid) >= sizeof(xspath) )
		ERR(goto done);

	if ( !xs_write(S->xh, XBT_NULL, xspath, "1", 1) )
		ERR(goto done);


	/* Setup grant page access. */
	if ( (S->gh = xengntshr_open(NULL, 0)) == NULL )
		ERR(goto done);

	if ( (S->gp = xengntshr_share_pages(S->gh, S->remote, 1, &gref, \
					    true)) == NULL )
		ERR(goto done);

	memset(S->gp, '\0', 4096);
	S->sp	= S->gp + sizeof(uint32_t);
	S->bufr = S->sp + sizeof(_Bool);


	/* Setup event channel. */
	if ( (S->evh = xenevtchn_open(NULL, 0)) == NULL )
		ERR(goto done);

	if ( (S->evp = xenevtchn_bind_unbound_port(S->evh, S->remote)) == -1 )
		ERR(goto done);


	/* Update SanchoXen xenstore with grant reference. */
	if ( snprintf(xspath, sizeof(xspath),				 \
		      "/local/domain/%s/backend/SanchoXen/%s/grant-ref", \
		      path, S->domid) >= sizeof(xspath) )
		ERR(goto done);

	if ( snprintf(xsvalue, sizeof(xsvalue), "%u", gref) >= \
	     sizeof(xsvalue) )
		ERR(goto done);

	if ( !xs_write(S->xh, XBT_NULL, xspath, xsvalue, strlen(xsvalue)) )
		ERR(goto done);


	/* Update SanchoXen xenstore with event channel. */
	if ( snprintf(xspath, sizeof(xspath),				     \
		      "/local/domain/%u/backend/SanchoXen/%s/event-channel", \
		      S->remote, S->domid) >= sizeof(xspath) )
		ERR(goto done);

	if ( snprintf(xsvalue, sizeof(xsvalue), "%u", S->evp) >= \
	     sizeof(xsvalue) )
		ERR(goto done);

	if ( !xs_write(S->xh, XBT_NULL, xspath, xsvalue, strlen(xsvalue)) )
		ERR(goto done);


	/* Wait for connection response and then confirm. */
	if ( xenevtchn_unmask(S->evh, S->evp) == -1 )
		ERR(goto done);
	if ( xenevtchn_pending(S->evh) == -1 )
		ERR(goto done);

	*S->sp = true;
	retn   = true;


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
	return true;
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
	*(uint32_t *) S->gp = size;
	*S->sp		    = false;

	if ( xenevtchn_notify(S->evh, S->evp) == -1 )
		fprintf(stdout, "%s: Failed notify at %d\n", __func__, \
			__LINE__);

	while ( !*S->sp ) {
		xen_mb();
		continue;
	}

	*S->sp = false;
	xen_mb();

	retn = true;


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

	xenevtchn_port_or_error_t port;


	/* Verify arguments. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf) )
		ERR(goto done);


	/* Wait for signal from the stubdomain. */
	if ( xenevtchn_unmask(S->evh, S->evp) == -1 )
		ERR(goto done);
	if ( (port = xenevtchn_pending(S->evh)) == -1 )
		ERR(goto done);

	rsize = *(uint32_t *) S->gp;


	/*
	 * Get the size of the buffer to be received and convert the
	 * network byte order value to a host integer. If more then
	 * the object specified amount is specified set the errno
	 * variable to be a negative value so it can be distinguished
	 * from a standard error number.
	 */
	rsize = ntohl(rsize);
	if ( rsize == 0 ) {
		retn   = true;
		S->eof = true;
		goto done;
	}
	if ( rsize > MAX_RECEIVE_SIZE )
		ERR(goto done);


	/* Load the received data into a Buffer object. */
	if ( !bf->add(bf, S->bufr, rsize) )
		ERR(goto done);
	memset(S->gp, '\0', 4096);

	*S->sp = true;
	xen_mb();

	while ( *S->sp ) {
		xen_mb();
		continue;
	}

	retn  = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
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

	String str = NULL;


	/* Send shutdown command to stubdomain. */
	*(uint32_t *) S->gp = 0xffffffff;


	/* Remove xenstore nodes. */
	INIT(HurdLib, String, str, goto release);
	if ( str->add_sprintf(str, "/local/domain/%u/backend/SanchoXen/%s/grant-ref", \
			      S->remote, S->domid) )
		xs_rm(S->xh, XBT_NULL, str->get(str));

	str->reset(str);
	if ( str->add_sprintf(str, "/local/domain/%u/backend/SanchoXen/%s/event-channel", \
			      S->remote, S->domid) )
		xs_rm(S->xh, XBT_NULL, str->get(str));


	xenevtchn_notify(S->evh, S->evp);
	xenevtchn_unmask(S->evh, S->evp);
	xenevtchn_pending(S->evh);


 release:
	/* Release resources. */
	xs_close(S->xh);
	xengntshr_unshare(S->gh, S->gp, 1);
	xengntshr_close(S->gh);

	S->root->whack(S->root, this, S);

	WHACK(str);

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

	this->whack		= whack;

	return this;
}
