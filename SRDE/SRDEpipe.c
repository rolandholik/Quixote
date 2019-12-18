/** \file
 * This file contains the implementation of an object used to
 * local enclave<->enclave communications.  Its primary role is to
 * be an object that is used be the SRDEpipe_mgr in order to
 * communication state between two enclaves in standard userspace.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "SRDE.h"
#include "SRDEenclave.h"
#include "SRDEocall.h"
#include "SRDEpipe.h"
#include "SRDEfusion-ocall.h"
#include "SRDEnaaaim-ocall.h"


/* Object state extraction macro. */
#define STATE(var) CO(SRDEpipe_State, var) = this->state


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_SRDEpipe_OBJID)
#error Object identifier not defined.
#endif


/** SRDEpipe private state information. */
struct NAAAIM_SRDEpipe_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Object status. */
	_Bool poisoned;

	/* ECALL slot number to communicate with. */
	int slot;

	/* Enclave to be managed. */
	SRDEenclave enclave;

	/* Ocall table for target enclave. */
	SRDEocall ocall;

	struct OCALL_api *table;

	/* Buffer for packet I/O. */
	Buffer packet;
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_SRDEpipe_State
 * structure which holds state information for each instantiated object.
 *
 * \param S	A pointer to the object containing the state
 *		information which is to be initialized.
 */

static void _init_state(const SRDEpipe_State const S)

{
	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_SRDEpipe_OBJID;

	S->poisoned = false;

	S->enclave = NULL;

	S->ocall = NULL;
	S->table = NULL;

	S->packet = NULL;

	return;
}


/**
 * External public method.
 *
 * This method implements the initialization and setup of the enclave
 * that will be communicated with.
 *
 * \param this		A pointer to the object which is to have an
 *			enclave associated with it.
 *
 * \param name		A pointer to a null terminated buffer containing
 *			the pathname of the enclave to open.
 *
 * \param slot		The slot number of the enclave that will implement
 *			the pipe endpoint.
 *
 * \param token		A pointer to a null terminated buffer containing
 *			the pathname of the launch token to be used
 *			for initializing the enclave.
 *
 * \param debug		A flag to indicate whether or not the enclave
 *			is to be initialized in debug or production mode.
 *
 * \return		A false value is returned if an error is
 *			encountered in setting up the enclave.  A true
 *			value is returned to indicate that the enclave
 *			setup was successful and available for use.
 */

static _Bool setup(CO(SRDEpipe, this), CO(char *, name), const int slot, \
		   CO(char *, token), const _Bool debug)

{
	STATE(S);

	_Bool retn = false;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Set the slot number and initialize the enclave. */
	S->slot = slot;

	INIT(NAAAIM, SRDEenclave, S->enclave, ERR(goto done));
	if ( !S->enclave->setup(S->enclave, name, token, debug) )
		ERR(goto done);


	/* Setup the OCALL table. */
	INIT(NAAAIM, SRDEocall, S->ocall, ERR(goto done));

	S->ocall->add_table(S->ocall, SRDEfusion_ocall_table);
	S->ocall->add_table(S->ocall, SRDEnaaaim_ocall_table);

	if ( !S->ocall->get_table(S->ocall, &S->table) )
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
 * This method implements establishing the connection with the
 * communications endpoint via ECALL's from standard userspace.  This
 * method is used by the ->connect method in enclave context to
 * mediate the exchange of attesttsion information
 *
 * \param this		A pointer to the object which is to implement
 *			the connection.
 *
 * \param target	A pointer to the structure containing target
 *			information that an attestation report is to
 *			be generated against.
 *
 * \param report	A pointer to the structuring containing a local
 *			attestation report.
 *
 * \return		A false value is returned if an error is
 *			encountered in setting up the connection.  A
 *			true value is returned to indicate that the
 *			connection has been established and the
 *			security context is available for use.
 */

static _Bool bind(CO(SRDEpipe, this), struct SGX_targetinfo *target, \
		  struct SGX_report *report)

{
	STATE(S);

	_Bool retn = false;

	int rc;

	struct SRDEpipe_ecall ecall;


	/* Call the enclave slot to get target/report. */
	memset(&ecall, '\0', sizeof(struct SRDEpipe_ecall));
	ecall.target = *target;
	ecall.report = *report;

	if ( !S->enclave->boot_slot(S->enclave, S->slot, S->table, &ecall, \
				    &rc) )
		ERR(goto done);

	*target = ecall.target;
	*report = ecall.report;
	retn	= true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method is an API placeholder for the implementation of the
 * same method in enclave context that drives the creation of the
 * security context between the two endpoints.
 *
 * \param this	A pointer to the object which is to implement the
 *		connection.
 *
 * \return	A boolean value is universally returned in order to
 *		indicate that this method should not be invoked from
 *		standard userspace.
 */

static _Bool connect(CO(SRDEpipe, this))

{
	return false;
}


/**
 * External public method.
 *
 * This method is an API placeholder for the implementation of the
 * same method in enclave context that verifies the identity of the
 * endpoing that is establishing the connection.
 *
 * \param this		A pointer to the object which is to implement the
 *			connection.
 *
 * \param endpoints	The object containing the array of endpoint
 *			descriptors that the connection is to be validated
 *			against.
 *
 * \param status	A pointer to a boolean value that will be updated
 *			with whether or not a security context should
 *			be created for the endpoint.
 *
 * \return	A boolean value is universally returned in order to
 *		indicate that this method should not be invoked from
 *		standard userspace.
 */

static _Bool verify(CO(SRDEpipe, this), CO(Buffer, endpoints), _Bool status)

{
	return false;
}


/**
 * External public method.
 *
 * This method is an API placeholder for the implementation of the
 * same method in enclave context that accepts a connection from
 * an initiating enclave endpoint.
 *
 * \param this		A pointer to the object which is to implement the
 *			connection.
 *
 * \param target	A pointer to an enclave target information structure.
 *			This parameter is unused.
 *
 * \param report	A pointer to an enclave report information structure.
 *			This parameter is unused.
 *
 * \return	A boolean value is universally returned in order to
 *		indicate that this method should not be invoked from
 *		standard userspace.
 */

static _Bool accept(CO(SRDEpipe, this), struct SGX_targetinfo *target, \
		    struct SGX_report *report)

{
	return false;
}


/**
 * External public method.
 *
 * This method implements sending a packet to the target enclave
 * via an ECALL.
 *
 * \param this		A pointer to the object which is to initiate
 *			the send.
 *
 * \param type		This type value is ignored in the standard
 *			implementation of the object.
 *
 * \param packet	The object containing the packet data to
 *			be conveyed to the enclave.
 *
 * \return		A boolean value is returned to indicate the
 *			status of packet transmission.  A false value
 *			indicates an error occured during
 *			transmission.  A true value indicates the
 *			packet was successfully transmitted.
 */

static _Bool send_packet(CO(SRDEpipe, this), const SRDEpipe_type type, \
			 CO(Buffer, bufr))

{
	STATE(S);

	_Bool retn = false;

	int rc;

	Buffer lbufr = NULL;

	struct SRDEpipe_ecall ecall;


	/* Clone the input buffer in order to support resizing. */
	INIT(HurdLib, Buffer, lbufr, ERR(goto done));
	if ( !lbufr->add_Buffer(lbufr, bufr) )
		ERR(goto done);


	/* Call the enclave slot to get target/report. */
	memset(&ecall, '\0', sizeof(struct SRDEpipe_ecall));
	ecall.bufr	= lbufr->get(lbufr);
	ecall.bufr_size = lbufr->size(lbufr);

	if ( !S->enclave->boot_slot(S->enclave, S->slot, S->table, &ecall, \
				    &rc) )
		ERR(goto done);

	if ( ecall.needed > 0 ) {
		lbufr->reset(lbufr);
		while ( ecall.needed-- )
			lbufr->add(lbufr, (void *) "\0", 1);
		if ( lbufr->poisoned(lbufr) )
			ERR(goto done);

		ecall.bufr	= lbufr->get(lbufr);
		ecall.bufr_size = lbufr->size(lbufr);
		if ( !S->enclave->boot_slot(S->enclave, S->slot, S->table, \
					    &ecall, &rc) )
			ERR(goto done);
	}

	bufr->reset(bufr);
	if ( ecall.bufr_size > 0 ){
		if ( !bufr->add(bufr, lbufr->get(lbufr), ecall.bufr_size) )
			ERR(goto done);
	}

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	WHACK(lbufr);

	return retn;
}


/**
 * External public method.
 *
 * This method is an API placeholder for the implementation of the
 * same method in enclave context that receives a packet from
 * an initiating enclave endpoint.
 *
 * \param this		A pointer to the object which is to implement the
 *			connection.
 *
 * \param target	A pointer to an enclave target information structure.
 *			This parameter is unused.
 *
 * \param report	A pointer to an enclave report information structure.
 *			This parameter is unused.
 *
 * \return	An SRDEpipe_failure return code is universally returned.
 */

static SRDEpipe_type receive_packet(CO(SRDEpipe, this), CO(Buffer, bufr))

{
	return SRDEpipe_failure;
}


/**
 * External public method.
 *
 * This method is a non-functional placeholder method for the
 * corresponding method in the trusted implementation of the object.
 *
 * \param this	A pointer to the object that would be initiating a
 *		pipe close event.
 *
 * \return	A false value is universally returned.
 */

static _Bool close(CO(SRDEpipe, this))

{
	return false;
}


/**
 * External public method.
 *
 * This method is a non-functional placeholder method for the
 * corresponding method in the trusted implementation of the object.
 *
 * \param this	A pointer to the object whose connection state is to
 *		be interrogated.
 *
 * \return	A false value is universally returned.
 */

static _Bool connected(CO(SRDEpipe, this))

{
	return false;
}


/**
 * External public method.
 *
 * This method implements a destructor for an SRDEpipe object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(SRDEpipe, this))

{
	STATE(S);


	WHACK(S->enclave);
	WHACK(S->ocall);
	WHACK(S->packet);

	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a SRDEpipe object.
 *
 * \return	A pointer to the initialized SRDEpipe.  A null value
 *		indicates an error was encountered in object generation.
 */

extern SRDEpipe NAAAIM_SRDEpipe_Init(void)

{
	Origin root;

	SRDEpipe this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_SRDEpipe);
	retn.state_size   = sizeof(struct NAAAIM_SRDEpipe_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_SRDEpipe_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize aggregate objects. */

	/* Method initialization. */
	this->setup = setup;
	this->bind  = bind;

	this->connect = connect;
	this->accept  = accept;
	this->verify  = verify;

	this->send_packet    = send_packet;
	this->receive_packet = receive_packet;

	this->close	= close;
	this->connected = connected;
	this->whack	= whack;

	return this;
}
