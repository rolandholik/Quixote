/** \file
 * This file implements methods which encapsulate basic socket based
 * network communication primites.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
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
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

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


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Duct_OBJID)
#error Object identifier not defined.
#endif


/** Duct private state information. */
struct NAAAIM_Duct_State
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

	/* Address for server to listen on. */
	long server;

	/* Flag to indicate whether or not reverse DNS lookup is done. */
	_Bool do_reverse;

	/* Client ip and hostname .*/
	struct in_addr ipv4;
	Buffer client;

	/* Receive buffer. */
	unsigned char bufr[1024];
};


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
	S->sockt	= -1;
	S->fd		= -1;
	S->server	= INADDR_ANY;
	S->do_reverse	= false;
	S->ipv4.s_addr	= 0;
	S->client       = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method implements initialization of a port on which a server
 * Duct object listens for network connection requests.
 *
 * \param	A pointer to the state information for a server Duct
 *		object.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of port initialization.  A true value is used
 *		to indicate success.
 */

static _Bool _init_server_port(CO(Duct_State, S), const long server, \
			       const int port)

{
	_Bool retn = false;

	struct sockaddr_in sdef;


	memset(&sdef, '\0', sizeof(sdef));
	sdef.sin_family		= AF_INET;
	sdef.sin_port		= htons(port);
	sdef.sin_addr.s_addr	= server;

	if ( (S->sockt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 )
		ERR(goto done);
	if ( bind(S->sockt, (struct sockaddr *) &sdef, sizeof(sdef)) == -1 )
		ERR(goto done);
	if ( listen(S->sockt, 128) == -1 )
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
 * will attempt an SSL based connection.
 *
 * \param	A pointer to the state information for a client Duct
 *		object.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of port initialization.  A true value is used
 *		to indicate success.
 */

static _Bool _init_client_port(CO(Duct_State, S), CO(char *, host), \
			       const int port)

{
	_Bool retn = false;

	struct sockaddr_in sdef;

	struct hostent *hdef;


	/* Socket initialization. */
	memset(&sdef, '\0', sizeof(sdef));
	sdef.sin_family	= AF_INET;
	sdef.sin_port	= htons(port);

	if ( (hdef = gethostbyname2(host, AF_INET)) == NULL )
		ERR(goto done);
	sdef.sin_addr.s_addr = *((unsigned long *) hdef->h_addr_list[0]);

	if ( (S->sockt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 )
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

static _Bool init_server(CO(Duct, this))

{
	STATE(S);

	S->type	    = server;
	S->poisoned = false;

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

	struct hostent *hdef;


	if ( (hdef = gethostbyname2(addr, AF_INET)) == NULL )
		ERR(goto done);
	S->server = *((unsigned long *) hdef->h_addr_list[0]);

	retn = true;


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
	STATE(S);

	S->type	    = client;
	S->poisoned = false;

	return true;
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


	if ( S->poisoned )
		ERR(return retn);

	if ( S->type == server )
		retn = _init_server_port(S, S->server, port);
	else
		retn = _init_client_port(S, host, port);


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

	char host[256];
	static const char * const reverse = " [reverse disabled]";

	int client_size;

	struct sockaddr_in client;


	if ( S->poisoned )
		ERR(goto done);
	if ( S->sockt == -1 )
		ERR(goto done);

	client_size = sizeof(client);
	memset(&client, '\0', client_size);

	if ( (S->fd = accept(S->sockt, (struct sockaddr *) &client, \
			     (void *) &client_size)) == -1 )
		ERR(goto done);

	S->ipv4.s_addr = client.sin_addr.s_addr;
	if ( getnameinfo((struct sockaddr *) &client,			    \
			 sizeof(struct sockaddr), host, sizeof(host), NULL, \
			 0, S->do_reverse ? 0 : NI_NUMERICHOST) != 0 )
		ERR(goto done);
	if ( S->client == NULL ) {
		S->client = HurdLib_Buffer_Init();
		if ( S->client == NULL )
			ERR(goto done);
	}
	else
		S->client->reset(S->client);

	S->client->add(S->client, (unsigned char *) host, strlen(host));
	if ( !S->do_reverse )
		S->client->add(S->client, (unsigned char *) reverse, \
			       strlen(reverse));
	if ( !S->client->add(S->client, (unsigned char *) "\0", 1) )
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
 * Internal public method.
 *
 * This method is a helper method for the -receive_Buffer method and
 * is designed to encapsulate the actual read from the socket.  It
 * handles detection of SIGINT and issues with less then the specified
 * read being delivered.
 *
 * \param this		The Duct object from which data is to be read.
 *
 * \param bufr		The object that the data from the socket is
 *			be read into.
 *
 * \param outstanding	The number of bytes to be read from the socket.
 *
 * \return	A boolean value is used to indicate whether or not the
 *		read was successful.  A false value indicates a
 *		functional error was experienced during the read.  A
 *		true value indicates the read was successful.
 */

static _Bool _receive(CO(Duct, this), CO(Buffer, bufr), size_t outstanding)

{
	STATE(S);

	_Bool retn = false;

	size_t amt_read;


	while ( outstanding > 0 ) {
		memset(S->bufr, '\0', sizeof(S->bufr));
		if ( (amt_read = read(S->fd, S->bufr, outstanding)) == -1 ) {
			if ( errno == EINTR )
				continue;
			S->error = errno;
			ERR(goto done);
		}

		outstanding -= amt_read;
		if ( !bufr->add(bufr, S->bufr, amt_read) ) {
			S->error = -2;
			ERR(goto done);
		}
	}
	retn = true;


 done:
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


	/* Loop over the number of integral receive blocks. */
	blocks	 = rsize / sizeof(S->bufr);
	residual = rsize % sizeof(S->bufr);

	for (lp= 0; lp < blocks; ++lp) {
		if ( !_receive(this, bf, sizeof(S->bufr)) )
			ERR(goto done);
	}

	/* Read residual data. */
	if ( !_receive(this, bf, residual) )
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

	/* Sanity checks. */
	if ( S->poisoned )
		ERR(return NULL);
	if ( S->client == NULL )
		ERR(S->poisoned = true; return NULL);

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


	if ( S->poisoned )
		ERR(return);
	S->do_reverse = mode;

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
	STATE(S);


	S->eof = false;

	if ( (S->type == server) && (S->fd != -1) ) {
		sleep(3);
		close(S->fd);
		S->fd = -1;
	}
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
		if ( S->type == server ) {
			sleep(3);
			close(S->fd);
		}
	}

	shutdown(S->sockt, SHUT_RDWR);
	close(S->sockt);


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
}
