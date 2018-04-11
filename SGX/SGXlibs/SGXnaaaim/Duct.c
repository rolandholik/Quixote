/** \file
 * This file implements methods which encapsulate the OCALL's needed
 * to implement socket based network primitives via a Duct object
 * running in untrusted userspace.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "Duct.h"

/* State extraction macro. */
#define STATE(var) CO(Duct_State, var) = this->state

/* Maximum receive buffer size - 256K. */
#define MAX_RECEIVE_SIZE 262144


/*
 * The Intel SDK version of this function is being used until the
 * loader initialization issue is addressed.
 */
#if 0
static _Bool SGXidf_trusted_region(void *ptr, size_t size)

{
	_Bool retn = false;

	if ( ptr == NULL )
		goto done;
	if ( sgx_is_outside_enclave(ptr, size) )
		goto done;
	retn = true;
 done:
	return retn;
}
#endif


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Duct_OBJID)
#error Object identifier not defined.
#endif


/** Provide a local definition for the socket address. */
struct in_addr {
	uint32_t s_addr;
};


/** Duct private state information. */
struct NAAAIM_Duct_State
{
	/* The root object. */
	Origin root;

	/* Library identifier. */
	uint32_t libid;

	/* Object identifier. */
	uint32_t objid;

	/* Untrusted instance. */
	unsigned int instance;

	/* Object status. */
	_Bool poisoned;

	/* End of transmission flag. */
	_Bool eof;

	/* Error code. */
	int error;

	/* Object type, server or client. */
	enum {not_defined, server, client} type;

	/* Flag to indicate whether or not reverse DNS lookup is done. */
	_Bool do_reverse;

	/* Client ip and hostname .*/
	struct in_addr ipv4;
	Buffer client;

	/* Receive buffer. */
	unsigned char bufr[1024];
};


/**
 * Internal private function.
 *
 * This method is responsible for marshalling arguements and generating
 * the OCALL for the external methods call.
 *
 * \param ocp	A pointer to the data structure which is used to
 *		marshall the arguements into and out of the OCALL.
 *
 * \return	An integer value is used to indicate the status of
 *		the SGX call.  A value of zero indicate there was no
 *		error while a non-zero value, particularly negative
 *		indicates an error occurred in the call.  The return
 *		value from the external object is embedded in the
 *		data marshalling structure.
 */

static int duct_ocall(struct Duct_ocall *ocall)

{
	_Bool retn = false;

	int status = SGX_ERROR_INVALID_PARAMETER;

	size_t arena_size = sizeof(struct Duct_ocall);

	struct Duct_ocall *ocp = NULL;


	/* Verify arguements and set size of arena. */
	if ( ocall->ocall == Duct_send_buffer ) {
		if ( !sgx_is_within_enclave(ocall->bufr, ocall->size) )
			goto done;
		arena_size += ocall->size;
	}
	if ( ocall->ocall == Duct_set_server ) {
		if ( !sgx_is_within_enclave(ocall->hostname, \
					    strlen(ocall->hostname) + 1) )
			goto done;
		arena_size += strlen(ocall->hostname) + 1;
	}
	if ( ocall->ocall == Duct_init_port && (ocall->hostname != NULL) ) {
		if ( !sgx_is_within_enclave(ocall->hostname, \
					    strlen(ocall->hostname) + 1) )
			goto done;
		arena_size += strlen(ocall->hostname) + 1;
	}


	/* Allocate and initialize the outbound method structure. */
	if ( (ocp = sgx_ocalloc(arena_size)) == NULL )
		goto done;

	memset(ocp, '\0', arena_size);
	*ocp = *ocall;


	/* Setup arena and pointers to it. */
	if ( ocall->ocall == Duct_send_buffer ) {
		memcpy(ocp->arena, ocall->bufr, ocall->size);
		ocp->bufr = ocp->arena;
	}
	if ( ocall->ocall == Duct_set_server ) {
		memcpy(ocp->arena, ocp->hostname, strlen(ocp->hostname) + 1);
		ocp->hostname = (char *) ocp->arena;
	}
	if ( ocall->ocall == Duct_init_port && (ocp->hostname != NULL) ) {
		memcpy(ocp->arena, ocp->hostname, strlen(ocp->hostname) + 1);
		ocp->hostname = (char *) ocp->arena;
	}


	/* Call the SGX duct manager. */
	if ( (status = sgx_ocall(2, ocp)) == 0 ) {
		retn = true;
		*ocall = *ocp;
	}


 done:
	sgx_ocfree();

	if ( status != 0 )
		return status;
	if ( !retn )
		return SGX_ERROR_UNEXPECTED;
	return 0;
}


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_Duct_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(Duct_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Duct_OBJID;


	S->poisoned	= false;
	S->eof		= false;
	S->error	= 0;
	S->type		= not_defined;
	S->do_reverse	= false;
	S->ipv4.s_addr	= 0;
	S->client       = NULL;

	return;
}


/**
 * External public method.
 *
 * This method initializes the network object to run in server mode.
 *
 * \param this	The network object which is to be initialized.
 *
 * \return	A boolean value is returned to indicate whether or
 *		not the server initialization was successful.  A true
 *		value indicates the server was successfully initialized.
 */

static _Bool init_server(CO(Duct, this))

{
	STATE(S);

	_Bool retn = false;

	struct Duct_ocall ocall;


	S->type	    = server;
	S->poisoned = false;

	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_init_server;

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = ocall.retn;


 done:
	if ( !retn )
		S->poisoned = true;

	return true;
}


/**
 * External public method.
 *
 * This method sets the interface address on which a server instance will
 * listen.  The default is to listen on all available addresses.
 *
 * \param this	The object which is to be initialized as a client.
 *
 * \param addr	The address on which the server is to listen.
 *
 * \return	A boolean value is returned to indicate whether or
 *		not server initialization was successful.  A true
 *		value indicates the client was successfully initialized.
 */

static _Bool set_server(CO(Duct, this), CO(char *, addr))

{
	STATE(S);

	_Bool retn = false;

	struct Duct_ocall ocall;


	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall    = Duct_set_server;
	ocall.hostname = (char *) addr;

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = ocall.retn;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method initializes the network communications object to
 * initiate client connections.
 *
 * \param this	The object which is to be initialized as a client.
 *
 * \return	A boolean value is returned to indicate whether or
 *		not client initialization was successful.  A true
 *		value indicates the client was successfully initialized.
 */

static _Bool init_client(CO(Duct, this))

{
	_Bool retn = false;

	STATE(S);

	struct Duct_ocall ocall;


	/* Call the untrusted implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_init_client;

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = ocall.retn;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method initializes a network port for communications.
 *
 * \param this	The communications object for which a port is to be
 *		initialized.
 *
 * \param port	The port number to be used for communication.
 *
 * \return	If the port is successfully initialized a boolean true
 *		value is returned.  If the initialization is not
 *		successful a false value is returned and the object
 *		is poisoned.
 */

static _Bool init_port(CO(Duct, this), CO(char *, host), int const port)

{
	STATE(S);

	_Bool retn = false;

	struct Duct_ocall ocall;


	if ( S->poisoned )
		ERR(goto done);

	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall    = Duct_init_port;
	ocall.hostname = (char *) host;
	ocall.port     = port;

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = ocall.retn;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements accepting a connection on an initialized server
 * port.
 *
 * \param this	The communications object which is to accept a connection.
 *
 * \return	This call blocks until a connection occurs.  The file
 *		descriptor of the connected socket is returned.
 */

static _Bool accept_connection(CO(Duct, this))

{
	STATE(S);

	_Bool retn = false;

	struct Duct_ocall ocall;


	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_accept_connection;

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = ocall.retn;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements sending the contents of a specified Buffer object
 * over the connection represented by the callingn object.
 *
 * \param this	The Duct object over which the Buffer is to be sent.
 *
 * \return	A boolean value is used to indicate whether or the
 *		write was successful.  A true value indicates the
 *		transmission was successful.
 */

static _Bool send_Buffer(CO(Duct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	struct Duct_ocall ocall;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( bf->poisoned(bf) )
		ERR(goto done);


	/* Call the userspace implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_send_buffer;
	ocall.size  = bf->size(bf);
	ocall.bufr  = bf->get(bf);

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	retn = ocall.retn;


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
 * \param this	The Duct object from which data is to be read.
 *
 * \return	A boolean value is used to indicate whether or the
 *		read was successful.  A true value indicates the receive
 *		was successful.
 */

static _Bool receive_Buffer(CO(Duct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	struct Duct_ocall ocall;


	/* Verify object status and inputs. */
	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf) )
		ERR(goto done);


	/* Call the untrusted implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_receive_buffer;

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	if ( !ocall.retn )
		ERR(goto done);

	if ( !bf->add(bf, ocall.bufr, ocall.size) )
		ERR(goto done);
	retn = ocall.retn;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements returning the IPV4 address of a client
 * connection.
 *
 * \param this	The Duct object whose address is to be returned.
 *
 * \return	A pointer to the structure containing the IPV4
 *		address.
 */

static struct in_addr * get_ipv4(CO(Duct, this))

{
	STATE(S);

	struct Duct_ocall ocall;


	/* Verify object status. */
	if ( S->poisoned )
		ERR(goto done);


	/* Call the untrusted implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_get_ipv4;

	if ( duct_ocall(&ocall) != 0 )
		ERR(goto done);
	S->ipv4.s_addr = ocall.addr;


 done:
	return &S->ipv4;
}


/**
 * External public method.
 *
 * This method implements returning the hostname of the client which
 * initiated a connection to a Server object.
 *
 * \param this	The Duct object whose hostname is to be printed.
 *
 * \return	A pointer to a null-terminated character buffer containing
 *		the hostname.
 */

static char * get_client(CO(Duct, this))

{
	STATE(S);

	struct Duct_ocall ocall;


	/* Sanity checks. */
	if ( S->poisoned )
		ERR(return NULL);


	/* Call the untrusted implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_get_client;
	if ( duct_ocall(&ocall) != 0 )
		return NULL;
	if ( ocall.hostname == NULL )
		return NULL;

	if ( S->client == NULL ) {
		S->client = HurdLib_Buffer_Init();
		if ( S->client == NULL )
			return NULL;
	}
	else
		S->client->reset(S->client);

	if ( !S->client->add(S->client, (unsigned char *) ocall.hostname, \
			     strlen(ocall.hostname)) )
		return NULL;
	return (char *) S->client->get(S->client);
}


/**
 * External public method.
 *
 * This method implements querying for whether or not the end of
 * transmission from a client has been detected.
 *
 * \param this		The Duct object whose client status is to
 *			be determined.
 *
 * \return		A false value indicates that an end-of-duct
 *			condition has not been detected.  A true
 *			value indicates the counter-party has generated
 *			condition indicating the connection has
 *			been terminated.
 */

static _Bool eof(CO(Duct, this))

{
	STATE(S);

	struct Duct_ocall ocall;


	/* Call the untrusted implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_eof;
	if ( duct_ocall(&ocall) != 0 )
		S->eof = true;
	else
		S->eof = ocall.eof;

	return S->eof;
}


/**
 * External public method.
 *
 * This method implements setting of the flag which determines whether
 * or not reverse DNS lookups are done on the address of clients.
 *
 * \param this		The Duct object whose reverse DNS status is to
 *			be set.
 *
 * \param mode		The boolean value which indictes whether or
 *			not reverse lookups are to be done.  A true
 *			value, the default on object initialization,
 *			specifies that lookups are to be done.
 *
 * \return		No return value is defined.
 */

static void do_reverse(CO(Duct, this), const _Bool mode)

{
	STATE(S);

	struct Duct_ocall ocall;


	if ( S->poisoned )
		ERR(return);


	/* Call the untrusted implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_do_reverse;
	ocall.mode  = mode;
	duct_ocall(&ocall);

	return;
}


/**
 * External public method.
 *
 * This method implements resetting of a duct object.  Its primary use
 * is in a server object to reset the accepted file descriptor.
 *
 * \param this	The Duct object which is to be reset.
 *
 * \return	A boolean value is returned to indicate whether or not
 *		the reset was successful.  A true value indicates the
 *		reset was successful.
 */

static void reset(CO(Duct, this))

{
	struct Duct_ocall ocall;


	/* Call the untrusted implementation. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_reset;
	duct_ocall(&ocall);

	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a Duct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(Duct, this))

{
	STATE(S);

	struct Duct_ocall ocall;


	/* Release implementation object. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall    = Duct_whack;
	ocall.instance = S->instance;
	duct_ocall(&ocall);


	/* Destroy resources. */
	WHACK(S->client);
	S->root->whack(S->root, this, S);
	return;
}


/**
 * External constructor call.
 *
 * This function implements a constructor call for a Duct object.
 *
 * \return	A pointer to the initialized Duct.  A null value
 *		indicates an error was encountered in object generation.
 */

extern Duct NAAAIM_Duct_Init(void)

{
	Origin root;

	Duct this = NULL;

	struct HurdLib_Origin_Retn retn;

	struct Duct_ocall ocall;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_Duct);
	retn.state_size   = sizeof(struct NAAAIM_Duct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_Duct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Initialize the untrusted object. */
	memset(&ocall, '\0', sizeof(struct Duct_ocall));
	ocall.ocall = Duct_init;
	if ( duct_ocall(&ocall) != 0 )
		goto err;
	this->state->instance = ocall.instance;

	/* Method initialization. */
	this->init_server	= init_server;
	this->init_client	= init_client;
	this->set_server	= set_server;

	this->init_port		= init_port;
	this->accept_connection	= accept_connection;

	this->send_Buffer	= send_Buffer;
	this->receive_Buffer	= receive_Buffer;

	this->get_ipv4		= get_ipv4;
	this->get_client	= get_client;

	this->eof		= eof;
	this->do_reverse	= do_reverse;

	this->reset		= reset;
	this->whack		= whack;

	return this;


 err:
	root->whack(root, this, this->state);
	return NULL;
}
