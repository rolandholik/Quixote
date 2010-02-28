/** \file
 *
 */

/**************************************************************************
 * (C)Copyright 2010, The Open Hurderos Foundation. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Include files. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#include <Origin.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "Duct.h"


/* Verify library/object header file inclusions. */
#if !defined(NAAAIM_LIBID)
#error Library identifier not defined.
#endif

#if !defined(NAAAIM_Duct_OBJID)
#error Object identifier not defined.
#endif


/** Diffie-Hellman key exchange parameters. */
static unsigned char dhp[] = {
        0xDA, 0x58, 0x3C, 0x16, 0xD9, 0x85, 0x22, 0x89, 0xD0, 0xE4, 0xAF, \
	0x75, 0x6F, 0x4C, 0xCA, 0x92, 0xDD, 0x4B, 0xE5, 0x33, 0xB8, 0x04, \
	0xFB, 0x0F, 0xED, 0x94, 0xEF, 0x9C, 0x8A, 0x44, 0x03, 0xED, 0x57, \
	0x46, 0x50, 0xD3, 0x69, 0x99, 0xDB, 0x29, 0xD7, 0x76, 0x27, 0x6B, \
	0xA2, 0xD3, 0xD4, 0x12, 0xE2, 0x18, 0xF4, 0xDD, 0x1E, 0x08, 0x4C, \
	0xF6, 0xD8, 0x00, 0x3E, 0x7C, 0x47, 0x74, 0xE8, 0x33
};

static unsigned char dhg[] = {
	0x02
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

	/* Object status. */
	_Bool poisoned;

	/* Object type, server or client. */
	enum {not_defined, server, client} type;

	/* SSL protocol type. */
	SSL_METHOD *method;

	/* SSL context. */
	SSL_CTX *context;

	/* SSL context identification. */
	unsigned int context_id;

	/* SSL connection. */
	SSL *connection;

	/* Socket file descriptor. */
	int sockt;

	/* Server file descriptor. */
	int fd;

	/* Client hostname .*/
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

static void _init_state(const Duct_State const S) {

	S->libid = NAAAIM_LIBID;
	S->objid = NAAAIM_Duct_OBJID;


	S->poisoned	= true;
	S->type		= not_defined;
	S->method	= NULL;
	S->context	= NULL;
	S->context_id	= 0;
	S->connection 	= NULL;
	S->sockt	= -1;
	S->fd		= -1;
	S->client       = NULL;

	return;
}


/**
 * Internal private method.
 *
 * This method implements initialization of the cryptographic state for
 * this object.
 *
 * \param	A pointer to the state information which is to be
 *		initialized.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of the initialization.  A true value is used
 *		to indicate success.
 */

static _Bool _init_crypto(const Duct_State const S)

{
	 static _Bool initialized = false;


	 /* Initialize all the available digests. */
	 if ( !initialized ) {
		 SSL_load_error_strings();
		 OpenSSL_add_ssl_algorithms();
		 initialized = true;
	 }

	 return true;
}


/**
 * Internal private method.
 *
 * This method implements initialization of a port on which a server
 * Duct object listens for SSL connections.
 *
 * \param	A pointer to the state information for a server Duct
 *		object.
 *
 * \return	A boolean return value is used to indicate success or
 *		failure of port initialization.  A true value is used
 *		to indicate success.
 */

static _Bool _init_server_port(const Duct_State const S, const int port)

{
	auto _Bool retn = false;

	auto struct sockaddr_in sdef;


	memset(&sdef, '\0', sizeof(sdef));
	sdef.sin_family		= AF_INET;
	sdef.sin_port		= htons(port);
	sdef.sin_addr.s_addr	= INADDR_ANY;
	
	if ( (S->sockt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
		S->poisoned = true;
		goto done;
	}
	if ( bind(S->sockt, (struct sockaddr *) &sdef, sizeof(sdef)) == -1 ) {
		S->poisoned = true;
		goto done;
	}
	if ( listen(S->sockt, 128) == -1 ) {
		S->poisoned = true;
		goto done;
	}

	retn = true;


 done:
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

static _Bool _init_client_port(const Duct_State const S, \
			       const char * const host, const int port)

{
	auto _Bool retn = false;

	auto struct sockaddr_in sdef;

	auto struct hostent *hdef;


	/* Socket initialization. */
	memset(&sdef, '\0', sizeof(sdef));
	sdef.sin_family		= AF_INET;
	sdef.sin_port		= htons(port);

	if ( (hdef = gethostbyname2(host, AF_INET)) == NULL ) {
		S->poisoned = true;
		goto done;
	}
	sdef.sin_addr.s_addr = *((unsigned long *) hdef->h_addr_list[0]);
	
	if ( (S->sockt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
		S->poisoned = true;
		goto done;
	}

	if ( connect(S->sockt, (struct sockaddr *) &sdef, sizeof(sdef)) \
	     == -1 ) {
		S->poisoned = true;
		goto done;
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method initializes the object to be a server object.
 *
 * \param this	The Duct object which is to be initialized to be an
 *		SSL server.
 *
 * \return	A boolean value is returned to indicate whether or
 *		not the server initialization was successful.  A true
 *		value indicates the server was successfully initialized.
 */

static _Bool init_server(const Duct const this)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;

	auto DH *dfh;


	/* Initialize the SSL context. */
	S->method = SSLv3_server_method();
	if ( (S->context = SSL_CTX_new(S->method)) == NULL ) {
		S->poisoned = true;
		goto done;
	}

	/* Set Diffie-Hellman key exchange parameters. */
	if ( (dfh = DH_new()) == NULL ) {
		S->poisoned = true;
		goto done;
	}

	dfh->p = BN_bin2bn(dhp, sizeof(dhp), NULL);
	dfh->g = BN_bin2bn(dhg, sizeof(dhg), NULL);
	if ( (dfh->p == NULL) || (dfh->g == NULL) ) {
		S->poisoned = true;
		goto done;
	}
	if ( SSL_CTX_set_tmp_dh(S->context, dfh) != 1 ) {
		S->poisoned = true;
		goto done;
	}

	/* Set session identification for this context. */
	S->context_id = 0xbeaf;
	if ( SSL_CTX_set_session_id_context(S->context,			      \
				      (const unsigned char *) &S->context_id, \
				      sizeof(S->context_id)) != 1 ) {
		S->poisoned = true;
		goto done;
	}

	retn 	    = true;
	S->type	    = server;
	S->poisoned = false;


 done:
	if ( retn == false )
		ERR_print_errors_fp(stderr);
	return retn;
}


/**
 * External public method.
 *
 * This method initializes the object to be a client object.
 *
 * \param this	The Duct object which is to be initialized to be an
 *		SSL client.
 *
 * \return	A boolean value is returned to indicate whether or
 *		not client initialization was successful.  A true
 *		value indicates the client was successfully initialized.
 */

static _Bool init_client(const Duct const this)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;


	/* Initialize the SSL context. */
	S->method = SSLv3_client_method();
	if ( (S->context = SSL_CTX_new(S->method)) == NULL ) {
		S->poisoned = true;
		goto done;
	}

	retn	    = true;
	S->type	    = client;
	S->poisoned = false;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements loading credentials in the form of an RSA
 * private key and a certificate into the SSL communications object.
 *
 * \param this	The object into which the credentials are to be loaded.
 *
 * \param key	A null-terminated character buffer containing the name
 *		of the file containing the PEM encoded private key.
 *
 * \param cert	A null-terminated character buffer containing the name
 *		of the file containing the PEM encoded certificate.
 *
 * \return	If the load of the file succeeds a boolean true value
 *		is returned to the caller.  If either load fails the
 *		object is poisoned and a boolean false value is
 *		returned.
 */

static _Bool load_credentials(const Duct const this, const char * const key, \
			      const char * const cert)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		goto done;

	if ( SSL_CTX_use_PrivateKey_file(S->context, key, SSL_FILETYPE_PEM) \
	     != 1 ) {
		S->poisoned = true;
		goto done;
	}

	if ( SSL_CTX_use_certificate_file(S->context, cert, SSL_FILETYPE_PEM) \
	     != 1 ) {
		S->poisoned = true;
		goto done;
	}
	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements the loading of certificates which will be used
 * to verify the SSL peer.
 *
 * \param this	The Duct object into which the certificates will be
 *		loaded.
 *
 * \param certfile	A null-terminated character buffer containing the
 *			name of the file containing the PEM encoded
 *			certificates.
 *
 * \return	If the load of the certificates succeeds a boolean true
 *		value is returned to the caller.  If either load fails the
 *		object is poisoned and a boolean false value is
 *		returned.
 */

static _Bool load_certificates(const Duct const this, \
			       const char * const certfile)

{
	auto const Duct_State const S = this->state;


	if ( S->poisoned )
		return false;

	if ( SSL_CTX_load_verify_locations(S->context, certfile, NULL) == 0 ) {
		S->poisoned = true;
		return false;
	}
	SSL_CTX_set_verify(S->context, SSL_VERIFY_PEER, NULL);

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

static _Bool init_port(const Duct const this, const char * const host, \
		       int const port)

{
	auto _Bool retn = false;


	if ( this->state->poisoned ) 
		return retn;
		
	if ( this->state->type == server )
		retn = _init_server_port(this->state, port);
	else
		retn = _init_client_port(this->state, host, port);

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

static _Bool accept_connection(const Duct const this)

{
	auto const Duct_State const S = this->state;

	auto char *hp;

	auto int retn,
		 client_size;

	struct hostent *client_hostname;

	auto struct sockaddr_in client;


	if ( S->poisoned || (S->sockt == -1) )
		return false;

	client_size = sizeof(client);
	memset(&client, '\0', client_size);

	if ( (S->fd = accept(S->sockt, (struct sockaddr *) &client, \
			     (void *) &client_size)) == -1 ) {
		S->poisoned = true;
		goto done;
	}

	client_hostname = gethostbyaddr(&client.sin_addr, \
					sizeof(struct in_addr), AF_INET);
	hp = client_hostname->h_name;
	if ( S->client == NULL ) {
		S->client = HurdLib_Buffer_Init();
		if ( S->client == NULL )
			goto done;
	}
	else
		S->client->reset(S->client);

	S->client->add(S->client, (unsigned char *) hp, strlen(hp));
	if ( !S->client->add(S->client, (unsigned char *) "\0", 1) ) {
		S->poisoned = true;
		goto done;
	}


	/* Initiate an SSL connection and listen for a client handshake. */
	if ( (S->connection = SSL_new(S->context)) == NULL ) {
		S->poisoned = true;
		goto done;
	}

	if ( SSL_clear(S->connection) != 1 ) {
		S->poisoned = true;
		goto done;
	}

	SSL_set_accept_state(S->connection);

	if ( SSL_set_fd(S->connection, S->fd) != 1 ) {
		S->poisoned = true;
		goto done;
	}

	if ( (retn = SSL_accept(S->connection)) < 0 ) {
		S->poisoned = true;
		goto done;
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements initiation of an SSL client connection to
 * a previously instituted socket connection.
 *
 * \param this	The client Duct object which is to initiate a connection.
 *
 * \return	A boolean value is used to indicate whether or not
 *		initiation of an SSL connection was successful.  A true
 *		value indicates the connection was successful.
 */

static _Bool init_connection(const Duct const this)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;

	auto int state;

	auto long verify;


	if ( S->poisoned )
		goto done;


	/* Initiate an SSL connection and listen for a client handshake. */
	if ( (S->connection = SSL_new(S->context)) == NULL ) {
		S->poisoned = true;
		goto done;
	}

	SSL_set_connect_state(S->connection);

	if ( SSL_set_fd(S->connection, S->sockt) != 1 ) {
		S->poisoned = true;
		goto done;
	}

	if ( (state = SSL_connect(S->connection)) < 0 ) {
		S->poisoned = true;
		goto done;
	}
	if ( state == 1 )
		S->fd = S->sockt;


	/* Check peer verification. */
	verify = SSL_get_verify_result(S->connection);
	if ( (verify == X509_V_OK) || (verify == 18) )
		retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method implements sending the contents of a specified Buffer object
 * over a previously established connection.
 *
 * \param this	The Duct object over which the Buffer is to be sent.
 *
 * \return	A boolean value is used to indicate whether or the
 *		write was successful.  A true value indicates the
 *		transmission was successful.
 */

static _Bool send_Buffer(const Duct const this, const Buffer bf)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;

	auto int state;

	auto uint32_t send_size = htonl(bf->size(bf));


	if ( S->poisoned || bf->poisoned(bf) )
		goto done;


	/* Send size of transmission. */
	state = SSL_write(S->connection, &send_size, sizeof(send_size));
	if ( state != sizeof(send_size) ) {
		S->poisoned = true;
		goto done;
	}

	state = SSL_write(S->connection, bf->get(bf), bf->size(bf));
	if ( state == bf->size(bf) ) {
		retn = true;
		goto done;
	}


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

static _Bool receive_Buffer(const Duct const this, const Buffer bf)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;

	auto unsigned char rbufr[1];

	auto int state;

	auto uint32_t receive_size;


	if ( S->poisoned || bf->poisoned(bf) || (S->fd == -1 ) )
		goto done;


	/* Get the size of the buffer to be received. */
	state = SSL_read(S->connection, &receive_size, sizeof(receive_size));
	if ( state != sizeof(receive_size) ) {
		S->poisoned = true;
		goto done;
	}
	receive_size = ntohl(receive_size);

	while ( receive_size-- > 0 ) {
		state = SSL_read(S->connection, rbufr, sizeof(rbufr));
		if ( state == 1 )
			bf->add(bf, rbufr, sizeof(rbufr));
		if ( state <= 0 )
			goto done;
	}

	retn = true;


 done:
	return retn;
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

static char * get_client(const Duct const this)

{
	/* Sanity checks. */
	if ( this->state->poisoned )
		return NULL;
	if ( this->state->client == NULL ) {
		this->state->poisoned = true;
		return NULL;
	}

	return (char *) this->state->client->get(this->state->client);
}
	

/**
 * External public method.
 *
 * This method implements resetting of a duct object.  In the case of
 * a server object the reset method is used to close the file descriptor
 * associated with a connection which has been accepted.
 *
 * \param this	The Duct object which is to be reset.
 *
 * \return	A boolean value is returned to indicate whether or not
 *		the reset was successful.  A true value indicates the
 *		reset was successful.
 */

static _Bool reset(const Duct const this)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;


	if ( S->poisoned )
		return false;

	if ( S->type == server ) {
		SSL_free(S->connection);
		S->connection = NULL;

		if ( (S->fd != -1) && (close(this->state->fd) == -1) )
			goto done;
	}

	retn = true;


 done:
	return retn;
}


/**
 * External public method.
 *
 * This method shuts down the SSL transport connection between two
 * connected peers.
 *
 * \param this	The Duct object whose transport layer is to be
 *		shutdown.
 */

static _Bool whack_connection(const Duct const this)

{
	auto const Duct_State const S = this->state;

	auto _Bool retn = false;

	auto int state;


	if ( S->poisoned )
		goto done;

	if ( (state = SSL_shutdown(S->connection)) == -1 ) {
		S->poisoned = true;
		goto done;
	}

	if ( (state == 0 ) && (state = SSL_shutdown(S->connection)) != 1 ) {
		S->poisoned = true;
		goto done;
	}

	retn = true;

 done:
	return retn;
}
			
			
/**
 * External public method.
 *
 * This method implements a destructor for a Duct object.
 *
 * \param this	A pointer to the object which is to be destroyed.
 */

static void whack(const Duct const this)

{
	auto const Duct_State const S = this->state;


	/* Free loaded error strings. */
	ERR_free_strings();

	/* Free client hostname if it has been defined. */
	if ( S->client != NULL )
		S->client->whack(S->client);

	/* Free SSL connection if one has been established. */
	if ( S->connection != NULL )
		SSL_free(S->connection);

	/* Free SSL context. */
	if ( S->context != NULL )
		SSL_CTX_free(S->context);

	/* Close listening socket. */
	if ( (S->type == server) && (S->fd != -1) )
		close(S->fd);
	if ( S->sockt != -1 )
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
	auto Origin root;

	auto Duct this = NULL;

	auto struct HurdLib_Origin_Retn retn;


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

	/* Initilize cryptographic state .*/
	if ( !_init_crypto(this->state) ) {
		root->whack(root, this, this->state);
		return NULL;
	}

	/* Method initialization. */
	this->init_server 	= init_server;
	this->load_credentials  = load_credentials;
	this->load_certificates	= load_certificates;
	this->init_port		= init_port;
	this->init_client      	= init_client;

	this->accept_connection	= accept_connection;
	this->init_connection	= init_connection;

	this->send_Buffer	= send_Buffer;
	this->receive_Buffer	= receive_Buffer;

	this->get_client	= get_client;

	this->reset		= reset;

	this->whack_connection	= whack_connection;
	this->whack		= whack;

	return this;
}
