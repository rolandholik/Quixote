/** \file
 * This file implements methods which encapsulate basic UNIX domain
 * network socket communication privimites.  It is designed to implement
 * the local equivalent of Duct objects.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "LocalDuct.h"

/* State extraction macro. */
#define STATE(var) CO(LocalDuct_State, var) = this->state

/* Maximum receive buffer size - 256K. */
#define MAX_RECEIVE_SIZE 262144


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_LocalDuct_OBJID)
#error Object identifier not defined.
#endif


/** LocalDuct private state information. */
struct NAAAIM_LocalDuct_State
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

	/* Error code. */
	int error;

	/* Object type, server or client. */
	enum {not_defined, server, client} type;

	/* Socket file descriptor. */
	int sockt;

	/* Server file descriptor. */
	int fd;

	/* Path to the socket. */
	String path;

	/* Receive buffer. */
	unsigned char bufr[1024];
};


/**
 * Internal private method.
 *
 * This method is responsible for initializing the NAAAIM_LocalDuct_State
 * structure which holds state information for each instantiated object.
 * The object is started out in poisoned state to catch any attempt
 * to use the object without initializing it.
 *
 * \param S A pointer to the object containing the state information which
 *        is to be initialized.
 */

static void _init_state(CO(LocalDuct_State, S)) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_LocalDuct_OBJID;


	S->poisoned	= false;
	S->eof		= false;
	S->error	= 0;
	S->type		= not_defined;
	S->sockt	= -1;
	S->fd		= -1;
	S->path		= NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method implements initialization of a port on which a server
 * LocalDuct object listens for network connection requests.
 *
 * \param	A pointer to the state information for a server LocalDuct
 *		object.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of port initialization.  A true value is used
 *		to indicate success.
 */

static _Bool _init_server_port(CO(LocalDuct_State, S), CO(char *, path))

{
	_Bool retn = false;

	struct sockaddr_un sdef;


	memset(&sdef, '\0', sizeof(sdef));
	sdef.sun_family	= AF_UNIX;
	
	if ( strlen(path) > (sizeof(sdef.sun_path) - 1) )
		ERR(goto done);
	snprintf(sdef.sun_path, sizeof(sdef.sun_path), "%s", path);
	

	if ( (S->sockt = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 )
		ERR(goto done);
	if ( bind(S->sockt, (struct sockaddr *) &sdef, sizeof(sdef)) == -1 )
		ERR(goto done);
	if ( listen(S->sockt, 5) == -1 )
		ERR(goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * Internal private method.
 *
 * This method implements initialization of a port on which a client
 * will attempt a connection.
 *
 * \param	A pointer to the state information for a client LocalDuct
 *		object.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of port initialization.  A true value is used
 *		to indicate success.
 */

static _Bool _init_client_port(CO(LocalDuct_State, S), CO(char *, path))

{
	_Bool retn = false;

	struct sockaddr_un sdef;


	/* Socket initialization. */
	memset(&sdef, '\0', sizeof(sdef));
	sdef.sun_family	= AF_UNIX;
	
	if ( strlen(path) > (sizeof(sdef.sun_path) - 1) )
		ERR(goto done);
	snprintf(sdef.sun_path, sizeof(sdef.sun_path), "%s", path);


	if ( (S->sockt = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 )
		ERR(goto done);

	if ( connect(S->sockt, (struct sockaddr *) &sdef, sizeof(sdef)) \
	     == -1 )
		ERR(goto done);
	S->fd = S->sockt;

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
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

static _Bool init_server(CO(LocalDuct, this))

{
	STATE(S);

	S->type	    = server;
	S->poisoned = false;

	return true;
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

static _Bool init_client(CO(LocalDuct, this))

{
	STATE(S);

	S->type	    = client;
	S->poisoned = false;

	return true;
}


/**
 * External public method.
 *
 * This method initializes a local port for communications.
 *
 * \param this	The communications object for which a port is to be
 *		initialized.
 *
 * \param path	The socket path to be used for communication.
 *
 * \return	If the UNIX domain socket is successfully initialized
 *		a boolean true value is returned.  If the initialization
 *		is not successful a false value is returned and the
 *		object is poisoned.
 */

static _Bool init_port(CO(LocalDuct, this), CO(char *, path))

{
	STATE(S);

	_Bool retn = false;


	if ( S->poisoned )
		ERR(goto done);

	if ( (S->path = HurdLib_String_Init_cstr(path)) == NULL )
		ERR(goto done);

	if ( S->type == server )
		retn = _init_server_port(S, path);
	else
		retn = _init_client_port(S, path);


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

static _Bool accept_connection(CO(LocalDuct, this))

{
	STATE(S);

	_Bool retn = false;

	int client_size;

	struct sockaddr_un client;


	if ( S->poisoned )
		ERR(goto done);
	if ( S->sockt == -1 )
		ERR(goto done);

	client_size = sizeof(client);
	memset(&client, '\0', client_size);

	if ( (S->fd = accept(S->sockt, (struct sockaddr *) &client, \
			     (void *) &client_size)) == -1 )
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
 * This method implements sending the contents of a specified Buffer object
 * over the connection represented by the callingn object.
 *
 * \param this	The LocalDuct object over which the Buffer is to be sent.
 *
 * \return	A boolean value is used to indicate whether or the
 *		write was successful.  A true value indicates the
 *		transmission was successful.
 */

static _Bool send_Buffer(CO(LocalDuct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	struct iovec vector[2];

	uint32_t size = htonl(bf->size(bf));

	ssize_t sent;


	if ( S->poisoned )
		ERR(goto done);
	if ( S->fd == -1 )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf))
		ERR(goto done);


	/* Setup vectors for packet size and payload. */
	vector[0].iov_len  = sizeof(uint32_t);
	vector[0].iov_base = &size;

	vector[1].iov_len  = bf->size(bf);
	vector[1].iov_base = bf->get(bf);

	/* Transmit the vector. */
	sent = writev(S->fd, vector, 2);
	if ( sent != (vector[0].iov_len + vector[1].iov_len) )
		ERR(S->error = errno; goto done);

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

static _Bool receive_Buffer(CO(LocalDuct, this), CO(Buffer, bf))

{
	STATE(S);

	_Bool retn = false;

	uint32_t rsize;

	size_t lp,
	       blocks,
	       residual;


	if ( S->poisoned )
		ERR(goto done);
	if ( (bf == NULL) || bf->poisoned(bf) )
		ERR(goto done);


	/*
	 * Get the size of the buffer to be received and convert the
	 * network byte order value to a host integer. If more then
	 * the object specified amount is specified set the errno
	 * variable to be a negative value so it can be distinguished
	 * from a standard error number.
	 */
	if ( read(S->fd, &rsize, sizeof(rsize)) != sizeof(rsize) )
		ERR(S->error = errno; goto done);

	rsize = ntohl(rsize);
	if ( rsize == 0 ) {
		retn   = true;
		S->eof = true;
		goto done;
	}
	if ( rsize > MAX_RECEIVE_SIZE )
		ERR(S->error = -1; goto done);


	/* Loop over the number of integral receipt blocks. */
	blocks	 = rsize / sizeof(S->bufr);
	residual = rsize % sizeof(S->bufr);

	for (lp= 0; lp < blocks; ++lp) {
		if ( read(S->fd, S->bufr, sizeof(S->bufr)) != sizeof(S->bufr) )
			ERR(S->error = errno; goto done);
		if ( !bf->add(bf, S->bufr, sizeof(S->bufr)) )
			ERR(S->error = -2; goto done);
	}

	/* Field the residual data. */
	if ( read(S->fd, S->bufr, residual) != residual )
		ERR(S->error = errno; goto done);
	if ( !bf->add(bf, S->bufr, residual) )
		ERR(S->error = -2; goto done);

	retn = true;


 done:
	if ( !retn )
		S->poisoned = true;

	return retn;
}


/**
 * External public method.
 *
 * This method implements querying for whether or not the end of
 * transmission from a client has been detected.
 *
 * \param this		The LocalDuct object whose client status is to
 *			be determined.
 *
 * \return		A false value indicates that an end-of-duct
 *			condition has not been detected.  A true
 *			value indicates the counter-party has generated
 *			condition indicating the connection has
 *			been terminated.
 */

static _Bool eof(CO(LocalDuct, this))

{
	STATE(S);

	return S->eof;
}


/**
 * External public method.
 *
 * This method implements querying for the socket file descriptor
 * of the socket.  This is to faciliate polling of the socket for
 * connection requests.
 *
 * \param this		The LocalDuct object whose client status is to
 *			be determined.
 *
 * \return		A false value indicates that an error was
 *			encountered while obtaining the file descriptor.
 *			A true value indicates a valid file descriptor
 *			has been returned to the location specified by
 *			the pointer arguement to this method.
 */

static _Bool get_socket(CO(LocalDuct, this), int *fd)

{
	STATE(S);


	if ( S->poisoned ) {
		fprintf(stderr, "%s: Poisoned.\n", __func__);
		return false;
	}

	*fd = S->sockt;
	return true;
}


/**
 * External public method.
 *
 * This method implements querying for the file descriptor used for
 * communications with a client.
 *
 * \param this		The LocalDuct object whose file descriptor is
 *			to be returned.
 *
 * \return		A false value indicates that a file descriptor
 *			could not be retrieved.  A true value means a
 *			valid file descriptor has been placed in the
 *			location pointed to by the arguement to the
 *			function.
 */

static _Bool get_fd(CO(LocalDuct, this), int *fd)

{
	STATE(S);


	if ( S->poisoned )
		return false;

	*fd = S->fd;
	return true;
}


/**
 * External public method.
 *
 * This method implements resetting of a LocalDuct object.  Its primary use
 * is in a server object to reset the accepted file descriptor.
 *
 * \param this	The LocalDuct object which is to be reset.
 *
 * \return	A boolean value is returned to indicate whether or not
 *		the reset was successful.  A true value indicates the
 *		reset was successful.
 */

static void reset(CO(LocalDuct, this))

{
	STATE(S);


	S->eof = false;

	if ( (S->type == server) && (S->fd != -1) ) {
		close(S->fd);
		S->fd = -1;
	}
	return;
}


/**
 * External public method.
 *
 * This method implements a destructor for a LocalDuct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(CO(LocalDuct, this))

{
	STATE(S);

	uint32_t size = ntohl(0);


	/*
	 * If this is a client connection send a zero length write
	 * to trigger an end of transmission situation.
	 */
	if ( (S->type == client) && (S->fd != -1) )
		write(S->fd, &size, sizeof(size));

	/* Close the I/O socket. */
	if ( S->fd != -1 ) {
		shutdown(S->fd, SHUT_RDWR);
		close(S->fd);
	}
	shutdown(S->sockt, SHUT_RDWR);
	close(S->sockt);

	/* Unlink the socket if this is a server instance.. */
	if ( S->path != NULL ) {
		if ( S->type == server )
			unlink(S->path->get(S->path));
		S->path->whack(S->path);
	}

	/* Destroy resources. */
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

extern LocalDuct NAAAIM_LocalDuct_Init(void)

{
	Origin root;

	LocalDuct this = NULL;

	struct HurdLib_Origin_Retn retn;


	/* Get the root object. */
	root = HurdLib_Origin_Init();

	/* Allocate the object and internal state. */
	retn.object_size  = sizeof(struct NAAAIM_LocalDuct);
	retn.state_size   = sizeof(struct NAAAIM_LocalDuct_State);
	if ( !root->init(root, NAAAIM_LIBID, NAAAIM_LocalDuct_OBJID, &retn) )
		return NULL;
	this	    	  = retn.object;
	this->state 	  = retn.state;
	this->state->root = root;

	/* Initialize aggregate objects. */

	/* Initialize object state. */
	_init_state(this->state);

	/* Method initialization. */
	this->init_server	= init_server;
	this->init_client	= init_client;

	this->init_port		= init_port;
	this->accept_connection	= accept_connection;

	this->send_Buffer	= send_Buffer;
	this->receive_Buffer	= receive_Buffer;

	this->get_socket	= get_socket;
	this->get_fd		= get_fd;
	this->eof		= eof;

	this->reset		= reset;
	this->whack		= whack;

	return this;
}
