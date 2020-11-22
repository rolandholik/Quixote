/** \file
 * This file implements a server which accepts an ASCII encoded EDI
 * transaction, requests encryption of that transaction and transmits
 * the encrypted transaction to a remote reception node.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Config.h>
#include <Buffer.h>
#include <String.h>

#include <Duct.h>
#include <Curve25519.h>
#include <PossumPipe.h>

#include "edi.h"
#include "EDIpacket.h"


/* Variables static to this module. */
#if 0
static pid_t process_table[100];
#endif

static Duct Engine = NULL;

static PossumPipe Receiver = NULL;


#if 0
/**
 * Private function.
 *
 * This function initializes the process table.
 */

static void init_process_table(void)

{
	auto unsigned int lp;


	for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
		process_table[lp] = 0;
	return;
}


/**
 * Private function.
 *
 * This function adds an entry to the process state table.  It will
 * locate an empy slot in the table and place the PID of the dispatched
 * process in that slot.
 *
 * \param pid	The process ID to be placed in the table.
 */

static void add_process(pid_t pid)

{
	auto unsigned int lp;


	for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
		if ( process_table[lp] == 0 ) {
			process_table[lp] = pid;
			return;
		}
	return;
}


/**
 * Private function.
 *
 * This function reaps any available processes and updates its slot in
 * the process table.
 */

static void update_process_table(void)

{
	auto unsigned int lp;

	auto int pid,
		 status;


	while ( (pid = waitpid(-1, &status, WNOHANG)) > 0 )
		for (lp= 0; lp < sizeof(process_table)/sizeof(pid_t); ++lp)
			if ( process_table[lp] == pid ) {
				process_table[lp] = 0;
				fprintf(stdout, "%d terminated", pid);
				if ( !WIFEXITED(status) ) {
					fputs(" abnormally.\n", stdout);
					continue;
				}
				fprintf(stdout, ", status=%d\n", \
					WEXITSTATUS(status));
			}
	return;
}
#endif


/**
 * Private function.
 *
 * This function is called to handle a connection for an identity
 * generation request.
 *
 * \param receiver	The network connection to the EDI transaction
 *			receiver with which a session key should be
 *			established.
 *
 * \param engine	The network connection to the EDI encryption
 *			engine which will use the session key.
 *
 * \return		A false value is returned if an error occurs
 *			during the setup of the session key.  A true
 *			value means a session key has been terminated
 *			between the EDI receiver and encryption engine.
 */

static _Bool setup_session(CO(PossumPipe, receiver), CO(Duct, engine))

{
	_Bool retn = false;

	Buffer bufr   = NULL,
	       shared = NULL;

	Curve25519 dh = NULL;

	EDIpacket edi = NULL;


	/* Generate and send a DH public key to receiver. */
	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(HurdLib, Buffer, shared, goto done);

	INIT(NAAAIM, Curve25519, dh, goto done);
	if ( !dh->generate(dh) )
		goto done;

	INIT(NAAAIM, EDIpacket, edi, goto done);
	edi->set_type(edi, EDIpacket_getkey);
	edi->set_payload(edi, dh->get_public(dh));
	edi->encode_payload(edi, bufr);
	if ( !receiver->send_packet(receiver, PossumPipe_data, bufr) )
		goto done;

	/* Receive the public key and generate a shared secret. */
	bufr->reset(bufr);
	if ( !receiver->receive_packet(receiver, bufr) )
		goto done;
	if ( !dh->compute(dh, bufr, shared) )
		goto done;

	/* Send the shared secret to the engine. */
	bufr->reset(bufr);
	edi->reset(edi);
	edi->set_type(edi, EDIpacket_key);
	edi->set_payload(edi, shared);
	if ( !edi->encode_payload(edi, bufr) )
		goto done;
	if ( !engine->send_Buffer(engine, bufr) )
		goto done;

	retn = true;


 done:
	WHACK(bufr);
	WHACK(dh);
	WHACK(edi);

	return retn;
}


/**
 * Private function.
 *
 * This function is called to handle a connection for an identity
 * generation request.
 *
 * \param duct	The network connection object being used to handle
 *		the identity generation request.
 *
 * \return	No return value is defined.
 */

static void handle_connection(CO(Duct,duct))

{
	const char *OK = "OK";

	Buffer bufr = NULL;

	EDIpacket edi = NULL;


	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(NAAAIM, EDIpacket, edi, goto done);

	fprintf(stdout, "\n.%d: Processing EDI transmit request from %s.\n", \
		getpid(), duct->get_client(duct));

	/* Process incoming transactions in a loop. */
	while ( 1 ) {
		if ( !duct->receive_Buffer(duct, bufr) ) {
			fputs("Failed receive.\n", stderr);
			goto done;
		}
		if ( duct->eof(duct) )
			goto done;

		/* Send bufr to EDI encryption engine. */
		fputs("Sending transaction to encrypter.\n", stdout);
		edi->set_type(edi, EDIpacket_decrypted);
		edi->set_payload(edi, bufr);
		bufr->reset(bufr);
		edi->encode_payload(edi, bufr);
		fputs("Encoded payload.\n", stdout);
		edi->print(edi);
		if ( !Engine->send_Buffer(Engine, bufr) ) {
			fputs("Error sending buffer.\n", stderr);
			goto done;
		}

		bufr->reset(bufr);
		if ( !Engine->receive_Buffer(Engine, bufr) ) {
			fputs("Error receiving response from engine.\n", \
			      stderr);
			goto done;
		}

		/* Send encrypted response to EDI receiver. */
		fputs("Sending encrypted EDI packet to receiver.\n", stderr);
		edi->reset(edi);
		edi->decode_payload(edi, bufr);
		edi->print(edi);

		if ( !Receiver->send_packet(Receiver, PossumPipe_data, \
					    bufr) ) {
			fputs("Error sending request to receiver.\n", stderr);
			goto done;
		}

		bufr->reset(bufr);
		if ( !Receiver->receive_packet(Receiver, bufr) ) {
			fputs("Error receiving response from receiver.\n", \
			      stderr);
			goto done;
		}
		fputs("Receiver response:\n", stderr);
		bufr->hprint(bufr);

		/* Send response to client. */
		bufr->reset(bufr);
		if ( !bufr->add(bufr, (unsigned char *) OK, strlen(OK)) )
			goto done;
		if ( !duct->send_Buffer(duct, bufr) )
			goto done;
		fputs("Transaction complete.\n", stderr);

		bufr->reset(bufr);
		edi->reset(edi);
	}


 done:
	WHACK(bufr);
	WHACK(edi);

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *host	= NULL,
	     *engine	= NULL,
	     *receiver	= NULL,
	     *err	= NULL;

	int opt,
	    retn = 1;

	pid_t pid = 0;

	Duct duct = NULL;

	fputs("EDI transmitter started.\n", stdout);
	fflush(stdout);

	while ( (opt = getopt(argc, argv, "e:h:r:")) != EOF )
		switch ( opt ) {
			case 'e':
				engine = optarg;
				break;
			case 'h':
				host = optarg;
				break;
			case 'r':
				receiver = optarg;
				break;
		}

	/* Arguement verification. */
	if ( engine == NULL ) {
		fputs("No EDI engine specified.\n", stderr);
		goto done;
	}
	if ( host == NULL ) {
		fputs("No EDI access name specified.\n", stderr);
		goto done;
	}
	if ( receiver == NULL ) {
		fputs("No EDI target specified.\n", stderr);
		goto done;
	}


	/* Initialize process table. */
#if 0
	init_process_table();
#endif

	/* Initialize the connection to the EDI engine. */
	fputs("Pausing for engine.\n", stderr);
	sleep(10);
	INIT(NAAAIM, Duct, Engine, goto done);
	if ( !Engine->init_client(Engine) ) {
		fputs("Cannot initialize engine connection.\n", stderr);
		goto done;
	}
	if ( !Engine->init_port(Engine, engine, ENGINE_PORT) ) {
		fputs("Cannot initiate engine connection.\n", stderr);
		goto done;
	}

	/* Initialize the connection to the EDI receiver. */
	INIT(NAAAIM, PossumPipe, Receiver, goto done);
	if ( !Receiver->init_client(Receiver, receiver, RECEIVER_PORT) ) {
		fputs("Cannot initialize EDI receiver connection.\n", stderr);
		goto done;
	}
	if ( !Receiver->start_client_mode(Receiver) )
		goto done;

	/* Setup shared session state between the receiver and engine. */
	if ( !setup_session(Receiver, Engine) )
		goto done;

	/* Initialize the network port and wait for connections. */
	INIT(NAAAIM, Duct, duct, goto done);

	if ( !duct->init_server(duct) ) {
		fputs("Cannot set server mode.\n", stderr);
		goto done;
	}

	fprintf(stderr, "initializing server port: %s\n", host);
	if ( !duct->set_server(duct, host) ) {
		err = "Cannot set server name.";
		goto done;
	}

	if ( !duct->init_port(duct, NULL, ACCESS_PORT) ) {
		fputs("Cannot initialize access port.\n", stderr);
		goto done;
	}


	/* Process connections. */
	while ( 1 ) {
		if ( !duct->accept_connection(duct) ) {
			err = "Error on connection accept.";
			goto done;
		}

		handle_connection(duct);
		if ( !duct->eof(duct) ) {
			fputs("No end-of-duct detected.\n", stderr);
			goto done;
		}
		duct->reset(duct);
	}


 done:
	if ( err != NULL )
		fprintf(stderr, "!%s\n", err);

	WHACK(duct);
	WHACK(Receiver);
	WHACK(Engine);

	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
