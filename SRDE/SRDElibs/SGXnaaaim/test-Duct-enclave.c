/** \file
 * This file contains an implementation of a test harness for testing
 * the enclave version of the Duct object.  This object is used for
 * implementing network based communications from one enclave to
 * another.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions of messages to be sent. */
#define KEY1 "0000000000000000000000000000000000000000000000000000000000000000"
#define KEY2 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define CR "\n"
#define OK "OK\n"


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <HurdLib.h>
#include <Buffer.h>

#include "Duct.h"


/** Provide a local definition for the socket address structure. */
struct in_addr {
	uint32_t s_addr;
};


/**
 * ECALL 0
 *
 * This function implements the ecall entry point for a function which
 * implements the server side of the Duct test.
 *
 * \param port	The port number the server is to listen on.
 *
 * \return	A boolean value is used to indicate the status of the
 *		test.  A false value indicates an error was encountered
 *		while a true value indicates the test was successfully
 *		conducted.
 */

_Bool test_server(int port)

{
	_Bool retn = false;

	struct in_addr *addr;

	Buffer bufr = NULL;

	Duct server = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Duct, server, ERR(goto done));

	fprintf(stdout, "Server test: listening on port %d.\n", port);

	if ( !server->init_server(server) )
		ERR(goto done);

	if ( !server->init_port(server, NULL, port) ) {
		fputs("Cannot initialize port.\n", stderr);
		ERR(goto done);
	}

	if ( !server->accept_connection(server) ) {
		fputs("Error accepting connection.\n", stderr);
		ERR(goto done);
	}

	addr = server->get_ipv4(server);
	fprintf(stdout, "\nAccepted connection from: %x\n", addr->s_addr);

	if ( !server->receive_Buffer(server, bufr) ) {
		fputs("Error receiving data.\n", stderr);
		goto done;
	}
	fputs("\nReceived:\n", stdout);
	bufr->print(bufr);

	fputs("\nReceived:\n", stdout);
	bufr->reset(bufr);
	server->receive_Buffer(server, bufr);
	bufr->print(bufr);

	fputs("\nReceived:\n", stdout);
	bufr->reset(bufr);
	server->receive_Buffer(server, bufr);
	bufr->print(bufr);

	fputs("\nSending:\n", stdout);
	fprintf(stdout, "%s\n", OK);
	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) OK, strlen(OK));

	if ( !server->send_Buffer(server, bufr) ) {
		fputs("Error on final send.\n", stderr);
		goto done;
	}

	fputs("Server mode done.\n", stderr);
	retn = true;


 done:
	WHACK(bufr);
	WHACK(server);

	return retn;
}


/**
 * ECALL 1
 *
 * This function implements the ecall entry point for a function which
 * implements the client side of the Duct test.
 *
 *
 * \param hostname	A pointer to a null-terminated character buffer
 *			containing the hostname which the client is to
 *			connect to.
 *
 * \param port		The port number to connect to on the remote
 *			server.
 *
 * \return	A boolean value is used to indicate the status of the
 *		test.  A false value indicates an error was encountered
 *		while a true value indicates the test was successfully
 *		conducted.
 */

_Bool test_client(char *hostname, int port)

{
	_Bool retn = false;

	Buffer bufr = NULL;

	Duct client = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Duct, client, ERR(goto done));

	fprintf(stdout, "Client test: connecting to %s, port=%d.\n", \
		hostname, port);

	if ( !client->init_client(client) ) {
		fputs("Cannot initialize client mode.\n", stderr);
		goto done;
	}

	if ( !client->init_port(client, hostname, port) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	fputs("\nSending:\n", stdout);
	fprintf(stdout, "%s\n", KEY1);
	bufr->add_hexstring(bufr, KEY1);
	client->send_Buffer(client, bufr);

	fputs("\nSending carriage return.\n", stdout);
	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) CR, strlen(CR));
	client->send_Buffer(client, bufr);

	fputs("\nSending:\n", stdout);
	fprintf(stdout, "%s\n", KEY2);
	bufr->reset(bufr);
	bufr->add_hexstring(bufr, KEY2);
	client->send_Buffer(client, bufr);

	bufr->reset(bufr);
	if ( !client->receive_Buffer(client, bufr) ) {
		fputs("Client receive failed.\n", stderr);
		goto done;
	}
	bufr->add(bufr, (unsigned char *) "\0", 1);
	fputs("\nReceived:\n", stdout);
	fprintf(stdout, "%s", bufr->get(bufr));

	fputs("\nClient mode done.\n", stderr);
	retn = true;


 done:
	WHACK(bufr);
	WHACK(client);

	return retn;
}
