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
	const char *err = NULL;

	struct sockaddr_in sdef;


	memset(&sdef, '\0', sizeof(sdef));
	sdef.sin_family		= AF_INET;
	sdef.sin_port		= htons(port);
	sdef.sin_addr.s_addr	= server;
	
	if ( (S->sockt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
		err = "Socket creation failed.";
		goto done;
	}
	if ( bind(S->sockt, (struct sockaddr *) &sdef, sizeof(sdef)) == -1 ) {
		err = "Socket bind failed.";
		goto done;
	}
	if ( listen(S->sockt, 128) == -1 ) {
		err = "Socket listen failed.";
		goto done;
	}


 done:
	if ( err != NULL ) {
		fprintf(stderr, "!%s[%s]: %s\n", __FILE__, __func__, err);
		S->poisoned = true;
		return false;
	}

	return true;
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
	const char *err = NULL;

	struct sockaddr_in sdef;

	struct hostent *hdef;


	/* Socket initialization. */
	memset(&sdef, '\0', sizeof(sdef));
	sdef.sin_family	= AF_INET;
	sdef.sin_port	= htons(port);

	if ( (hdef = gethostbyname2(host, AF_INET)) == NULL ) {
		err = "Host lookup failed.";
		goto done;
	}
	sdef.sin_addr.s_addr = *((unsigned long *) hdef->h_addr_list[0]);
	
	if ( (S->sockt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
		err = "Socket creation failed.";
		goto done;
	}

	if ( connect(S->sockt, (struct sockaddr *) &sdef, sizeof(sdef)) \
	     == -1 ) {
		err = "Socket connection failed.";
		goto done;
	}

	S->fd = S->sockt;


 done:
	if ( err != NULL ) {
		fprintf(stderr, "!%s[%s]: %s\n", __FILE__, __func__, err);
		S->poisoned = true;
		return false;
	}

	return true;
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
		goto done;
	S->server = *((unsigned long *) hdef->h_addr_list[0]);
	retn = true;

 done:
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
		return retn;
		
	if ( S->type == server )
		retn = _init_server_port(S, S->server, port);
	else
		retn = _init_client_port(S, host, port);

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

	const char *err = NULL;

	char host[256];
	static const char * const reverse = " [reverse disabled]";

	int client_size;

	struct sockaddr_in client;


	if ( S->poisoned )
		return false;
	if ( S->sockt == -1 ) {
		S->poisoned = true;
		return false;
	}

	client_size = sizeof(client);
	memset(&client, '\0', client_size);

	if ( (S->fd = accept(S->sockt, (struct sockaddr *) &client, \
			     (void *) &client_size)) == -1 ) {
		err = "Socket accept failed.";
		goto done;
	}

	S->ipv4.s_addr = client.sin_addr.s_addr;
	if ( getnameinfo((struct sockaddr *) &client,			    \
			 sizeof(struct sockaddr), host, sizeof(host), NULL, \
			 0, S->do_reverse ? 0 : NI_NUMERICHOST) != 0 ) {
		err = "Name lookup failed.";
		goto done;
	}
	if ( S->client == NULL ) {
		S->client = HurdLib_Buffer_Init();
		if ( S->client == NULL ) {
			err = "Client object name initialization failed.";
			goto done;
		}
	}
	else
		S->client->reset(S->client);

	S->client->add(S->client, (unsigned char *) host, strlen(host));
	if ( !S->do_reverse )
		S->client->add(S->client, (unsigned char *) reverse, \
			       strlen(reverse));
	if ( !S->client->add(S->client, (unsigned char *) "\0", 1) ) {
		err = "Store of client named failed.";
		goto done;
	}


 done:
	if ( err != NULL ) {
		fprintf(stderr, "!%s[%s]: %s\n", __FILE__, __func__, err);
		S->poisoned = true;
		return false;
	}

	return true;
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

	uint32_t size = htonl(bf->size(bf));


	if ( S->poisoned )
		return false;
	if ( bf->poisoned(bf) || (S->fd == -1) )
		goto done;


	/* Send size of transmission. */
	if ( write(S->fd, &size, sizeof(size)) != sizeof(size) ) {
		S->error = errno;
		goto done;
	}

	/* Then the contents of the buffer. */
	if ( write(S->fd, bf->get(bf), bf->size(bf)) != bf->size(bf) ) {
		S->error = errno;
		goto done;
	}

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

	unsigned char rbufr[1];

	uint32_t rsize;


	if ( S->poisoned )
		return false;
	if ( bf->poisoned(bf) || (S->fd == -1) )
		goto done;


	/*
	 * Get the size of the buffer to be received and convert the
	 * network byte order value to a host integer. If more then
	 * the object specified amount is specified set the errno
	 * variable to be a negative value so it can be distinguished
	 * from a standard error number.
	 */
	if ( read(S->fd, &rsize, sizeof(rsize)) != sizeof(rsize) ) {
		S->error    = errno;
		goto done;
	}
	rsize = ntohl(rsize);
	if ( rsize > MAX_RECEIVE_SIZE ) {
		S->error    = -1;
		goto done;
	}	     


	/* Loop until we receive the specified number of bytes. */
	while ( rsize-- > 0 ) {
		if ( read(S->fd, rbufr, sizeof(rbufr)) != sizeof(rbufr) ) {
			S->error    = errno;
			goto done;
		}
		if ( !bf->add(bf, rbufr, sizeof(rbufr)) ) {
			S->error    = -2;
			goto done;
		}
	}

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
		return NULL;
	if ( S->client == NULL ) {
		S->poisoned = true;
		return NULL;
	}

	return (char *) S->client->get(S->client);
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
		return;
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


	if ( (S->type == server) && (S->fd != -1) ) {
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


	/* Free client hostname if it has been defined. */
	WHACK(S->client);

	/* Close the I/O socket. */
	if ( S->fd != -1 ) {
		shutdown(S->fd, SHUT_RDWR);
		if ( S->type == server )
			close(S->fd);
	}
	shutdown(S->sockt, SHUT_RDWR);
	close(S->sockt);

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

	this->do_reverse	= do_reverse;
	this->reset		= reset;
	this->whack		= whack;

	return this;
}
