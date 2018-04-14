/** \file
 * This file contains an implementation of a test harness for testing
 * the enclave version of the Duct object.  This object is used for
 * implementing network based communications from one enclave to
 * another.
 */

/**************************************************************************
 * (C)Copyright 2018, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
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

#include "PossumPipe.h"


/** Provide a local definition for the socket address structure. */
struct in_addr {
	uint32_t s_addr;
};


/**
 * Enumerated type to specify what mode the enclave is running in.
 */
enum test_mode {
	none,
	client,
	server
} Mode = none;


static _Bool ping(CO(PossumPipe, pipe))

{
	_Bool retn = false;

	Buffer bufr	 = NULL,
	       reference = NULL;


	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(HurdLib, Buffer, reference, goto done);

	if ( Mode == server ) {
		fputs("\nWaiting for ping packet.\n", stderr);
		if ( pipe->receive_packet(pipe, bufr) != PossumPipe_data ) {
			fputs("Error receiving packet.\n", stderr);
			goto done;
		}
		fputs("Received packet:\n", stdout);
		bufr->print(bufr);

		fputs("\nReturning packet.\n", stdout);
		if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) ) {
			fputs("Error sending packet.\n", stderr);
			goto done;
		}

		fputs("\nServer mode done.\n", stdout);
		retn = true;
	}

	if ( Mode == client ) {
		fputs("\nSending ping packet:\n", stderr);
		reference->add_hexstring(reference, KEY1);

		bufr->add_hexstring(bufr, KEY1);
		bufr->print(bufr);

		if ( !pipe->send_packet(pipe, PossumPipe_data, bufr) ) {
			fputs("Error sending data packet.\n", stderr);
			goto done;
		}

		fputs("\nWaiting for response:\n", stdout);
		bufr->reset(bufr);
		if ( pipe->receive_packet(pipe, bufr) != PossumPipe_data ) {
			fputs("Error receiving packet.\n", stderr);
			goto done;
		}

		if ( bufr->equal(bufr, reference) )
			fputs("\nPacket is verified.\n", stdout);
		else {
			fputs("\nPacket failed verification.\n", stdout);
			fputs("\nSent:\n", stdout);
			reference->print(reference);
			fputs("Received:\n", stdout);
			bufr->print(bufr);
		}

		fputs("\nClient mode done.\n", stdout);
		retn = true;
	}

 done:
	WHACK(bufr);
	WHACK(reference);

	return retn;
}


/**
 * ECALL 0
 *
 * This function implements the ecall entry point for a function which
 * implements the server side of the Duct test.
 *
 * \param port		The port number the server is to listen on.
 *
 * \param spid_key	A pointer to the Service Provider ID (SPID)
 *			encoded in ASCII hexadecimal form.
 *
 * \return	A boolean value is used to indicate the status of the
 *		test.  A false value indicates an error was encountered
 *		while a true value indicates the test was successfully
 *		conducted.
 */

_Bool test_server(int port, char *spid_key)

{
	_Bool retn = false;

	PossumPipe pipe = NULL;

	Buffer spid = NULL;


	/* Convert the SPID value into binary form. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spid_key) )
		ERR(goto done);


	/* Start the server listening. */
	fprintf(stdout, "Server mode: port=%d\n", port);

	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( !pipe->init_server(pipe, "localhost", port, false) )
		ERR(goto done);

	if ( !pipe->accept_connection(pipe) ) {
		fputs("Error accepting connection.\n", stderr);
		ERR(goto done);
	}

	if ( !pipe->start_host_mode(pipe, spid) ) {
		fputs("Error receiving data.\n", stderr);
		goto done;
	}

	Mode = server;
	ping(pipe);


 done:
	WHACK(spid);
	WHACK(pipe);

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
 * \param spid_key	A pointer to the Service Provider ID (SPID)
 *			encoded in ASCII hexadecimal form.
 *
 * \return	A boolean value is used to indicate the status of the
 *		test.  A false value indicates an error was encountered
 *		while a true value indicates the test was successfully
 *		conducted.
 */

_Bool test_client(char *hostname, int port, char *spid_key)

{
	_Bool retn = false;

	PossumPipe pipe = NULL;

	Buffer spid = NULL;


	/* Convert the SPID value into binary form. */
	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spid_key) )
		ERR(goto done);


	fprintf(stdout, "Client mode: connecting to %s:%d\n", hostname, port);
	INIT(NAAAIM, PossumPipe, pipe, ERR(goto done));
	if ( !pipe->init_client(pipe, hostname, port) ) {
		fputs("Cannot initialize client pipe.\n", stderr);
		goto done;
	}
	if ( !pipe->start_client_mode(pipe, spid)) {
		fputs("Error starting client mode.\n", stderr);
		goto done;
	}

	Mode = client;
	ping(pipe);

	retn = true;


 done:
	WHACK(spid);
	WHACK(pipe);

	return retn ? 0 : 1;
}
