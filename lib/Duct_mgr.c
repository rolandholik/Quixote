/** \file
 * This file implements a Duct manager which manages Duct objects on
 * behalf of a Duct object running in enclave context.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "Duct.h"


/** Duct objects under external management. */
static _Bool Duct_initialized = false;

static Buffer Duct_buffers[16];

static Duct Duct_objects[16];


/**
 * Internal private function.
 *
 * This function manages the initialization of a Duct object to
 * implement functionality for an enclave based Duct object.  The Duct
 * pointer is returned and stored in the enclave based object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_init(struct Duct_ocall *ocp)

{
	_Bool retn = false;

	unsigned int instance;

	Buffer buffer = NULL;

	Duct duct = NULL;


	for (instance= 0; instance < sizeof(Duct_objects)/sizeof(Duct); \
		     ++instance) {
		if ( Duct_objects[instance] == NULL )
			break;
	}
	if ( instance == sizeof(Duct_objects)/sizeof(Duct) )
		ERR(goto done);

	INIT(HurdLib, Buffer, buffer, ERR(goto done));
	INIT(NAAAIM, Duct, duct, ERR(goto done));
	ocp->instance		= instance;
	Duct_objects[instance]	= duct;
	Duct_buffers[instance]	= buffer;

	retn = true;


 done:
	if ( !retn ) {
		if ( (duct = Duct_objects[instance]) != NULL ) {
			WHACK(duct);
			Duct_objects[instance] = NULL;
		}
		if ( (buffer = Duct_buffers[instance]) != NULL ) {
			WHACK(buffer);
			Duct_buffers[instance] = NULL;
		}
	}
	ocp->retn = retn;

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->init_server method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_init_server(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	ocp->retn = duct->init_server(duct);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->init_client method for the enclave
 * based duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_init_client(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	ocp->retn = duct->init_client(duct);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->set_server method for the enclave
 * basec Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_set_server(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	ocp->retn = duct->set_server(duct, ocp->hostname);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->init_port method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_init_port(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	ocp->retn = duct->init_port(duct, ocp->hostname, ocp->port);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->accept_connection method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_get_ipv4(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];

	struct in_addr *addr;


	addr = duct->get_ipv4(duct);
	ocp->addr = addr->s_addr;
	ocp->retn = true;

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->get_client method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_get_client(struct Duct_ocall *ocp)

{
	char *client;

	Duct duct = Duct_objects[ocp->instance];

	Buffer bufr = Duct_buffers[ocp->instance];


	client = duct->get_client(duct);
	if ( client == NULL ) {
		ocp->hostname = NULL;
	} else {
		bufr->reset(bufr);
		if ( !bufr->add(bufr, (unsigned char *) client, \
				strlen(client) + 1) )
			ocp->hostname = NULL;
		else
			ocp->hostname = (char *) bufr->get(bufr);
	}

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->init_connection method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_init_connection(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	ocp->retn = duct->init_connection(duct);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->accept_connection method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_accept_connection(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	ocp->retn = duct->accept_connection(duct);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->receive_Buffer method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_receive_buffer(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];

	Buffer bufr = Duct_buffers[ocp->instance];


	bufr->reset(bufr);

	ocp->retn = duct->receive_Buffer(duct, bufr);
	if ( ocp->retn ) {
		ocp->size = bufr->size(bufr);
		ocp->bufr = bufr->get(bufr);
	}

	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->send_Buffer method for the enclave
 * based Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_send_buffer(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];

	Buffer bufr = Duct_buffers[ocp->instance];


	bufr->reset(bufr);
	if ( !bufr->add(bufr, ocp->bufr, ocp->size) ) {
		ocp->retn = false;
		goto done;
	}

	ocp->retn = duct->send_Buffer(duct, bufr);


 done:
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->eof method for the enclave based
 * Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_eof(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	ocp->eof = duct->eof(duct);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->do_reverse method for the enclave
 * based Duct objects.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_do_reverse(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	duct->do_reverse(duct, ocp->mode);
	return;
}


/**
 * Internal private function.
 *
 * This function implements the ->reset method for the enclave based
 * Duct object.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_reset(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];


	duct->reset(duct);
	return;
}


/**
 * Internal private function.
 *
 * This function manages the destruction of a Duct object which has
 * been previously initialized.
 *
 * \param ocp	A pointer to the structure which is marshalling the
 *		data into and out of the OCALL.
 *
 * \return	No return value is defined.
 */

static void duct_whack(struct Duct_ocall *ocp)

{
	Duct duct = Duct_objects[ocp->instance];

	Buffer buffer = Duct_buffers[ocp->instance];


	duct->whack(duct);
	buffer->whack(buffer);

	Duct_objects[ocp->instance] = NULL;
	Duct_buffers[ocp->instance] = NULL;

	return;
}


/**
 * External function.
 *
 * This function is the external entry point for the enclave OCALL
 * handler.
 *
 * \param ocp	A pointer to the structure which is used to marshall
 *		the data being submitted to and returned from the
 *		enclave OCALL handler.
 *
 * \return	If an error is encountered a non-zero value is
 *		returned to the caller.  Successful processing of
 *		the command returns a value of zero.
 */

int Duct_mgr(struct Duct_ocall *ocp)

{
	int rc = -1;


	/* Verify on first call that object array is initialized. */
	if ( !Duct_initialized ) {
		memset(Duct_objects, '\0', sizeof(Duct_objects));
		Duct_initialized = true;
	}


	/* Verify ocall method type and instance specification. */
	if ( (ocp->ocall < 0) || (ocp->ocall >= Duct_END) ) {
		fprintf(stderr, "Ocall: %d\n", ocp->ocall);
		ERR(goto done);
	}

	if ( ocp->instance >= sizeof(Duct_objects)/sizeof(Duct) )
		ERR(goto done);


	/* Vector execution to the appropriate method handler. */
	switch ( ocp->ocall ) {
		case Duct_init:
			duct_init(ocp);
			break;
		case Duct_init_server:
			duct_init_server(ocp);
			break;
		case Duct_init_client:
			duct_init_client(ocp);
			break;
		case Duct_set_server:
			duct_set_server(ocp);
			break;
		case Duct_init_port:
			duct_init_port(ocp);
			break;
		case Duct_accept_connection:
			duct_accept_connection(ocp);
			break;
		case Duct_init_connection:
			duct_init_connection(ocp);
			break;
		case Duct_send_buffer:
			duct_send_buffer(ocp);
			break;
		case Duct_receive_buffer:
			duct_receive_buffer(ocp);
			break;

		case Duct_get_ipv4:
			duct_get_ipv4(ocp);
			break;
		case Duct_get_client:
			duct_get_client(ocp);
			break;

		case Duct_do_reverse:
			duct_do_reverse(ocp);
			break;
		case Duct_eof:
			duct_eof(ocp);
			break;
		case Duct_reset:
			duct_reset(ocp);
			break;
		case Duct_whack:
			duct_whack(ocp);
			break;

		case Duct_END:
			break;
	}
	rc = 0;


 done:
	return rc;
}
