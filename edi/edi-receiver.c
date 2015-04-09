/** \file
 * This file implements a server which accepts an encrypted EDI
 * transaction and requests the decryption of the transaction against
 * the specified service identity.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
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
static pid_t process_table[100];

static Duct Engine   = NULL;


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


/**
 * Private function.
 *
 * This function is called to handle a connection for an identity
 * generation request.
 *
 * \param transmitter	The network connection to the EDI transaction
 *			transmitter with which a session key should be
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

static _Bool setup_session(CO(PossumPipe, transmitter), CO(Duct, engine))

{
	_Bool retn = false;

	Buffer bufr   = NULL,
	       shared = NULL;

	Curve25519 dh = NULL;

	EDIpacket edi = NULL;


	/* Receive packet from transmitter with DH public key. */
	INIT(HurdLib, Buffer, shared, goto done);
	INIT(HurdLib, Buffer, bufr, goto done);
	if ( !transmitter->receive_packet(transmitter, bufr) )
		goto done;

	INIT(NAAAIM, EDIpacket, edi, goto done);
	edi->decode_payload(edi, bufr);
	if ( edi->get_type(edi) != EDIpacket_getkey )
		goto done;
	bufr->reset(bufr);
	if ( !edi->get_payload(edi, bufr) )
		goto done;
	fprintf(stderr, "%s: DH key:\n", __func__);
	bufr->hprint(bufr);

	/* Generate local DH key and send public portion to transmitter. */
	INIT(NAAAIM, Curve25519, dh, goto done);
	dh->generate(dh);
	if ( !dh->compute(dh, bufr, shared) )
		goto done;
	fprintf(stderr, "%s: Shared secret:\n", __func__);
	shared->hprint(shared);
	if ( !transmitter->send_packet(transmitter, PossumPipe_data, \
				       dh->get_public(dh)) )
		goto done;
	fprintf(stderr, "%s: Transmitted public key.\n", __func__);

	/* Send the shared secret to the engine. */
	bufr->reset(bufr);
	edi->reset(edi);
	edi->set_type(edi, EDIpacket_key);
	edi->set_payload(edi, shared);
	if ( !edi->encode_payload(edi, bufr) )
		goto done;
	if ( !engine->send_Buffer(engine, bufr) )
		goto done;
	fprintf(stderr, "%s: Send shared secret to engine.\n", __func__);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(shared);
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

static void handle_connection(CO(PossumPipe, duct))

{
	const char *OK = "OK";

	Buffer bufr    = NULL;

	EDIpacket edi = NULL;


	/* Initialize connection. */
	fputs("Starting host mode\n", stderr);
	if ( !duct->start_host_mode(duct) )
		goto done;

	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(NAAAIM, EDIpacket, edi, goto done);

	fprintf(stdout, "\n.%d: Processing EDI receiver request from.\n", \
		getpid());

	if ( !setup_session(duct, Engine) )
		goto done;

	/* Process incoming transactions in a loop. */
	while ( 1 ) {
		fputs("Waiting for EDI reception.\n", stderr);
		if ( !duct->receive_packet(duct, bufr) )
			goto done;

		fputs("Sending transaction to engine.\n", stdout);
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

		/* Output EDI transaction. */
		if ( !edi->decode_payload(edi, bufr) )
			goto done;
		fputs("EDI transaction:\n", stderr);
		bufr->reset(bufr);
		edi->get_payload(edi, bufr);
		bufr->hprint(bufr);


		/* Send response to client. */
		bufr->reset(bufr);
		if ( !bufr->add(bufr, (unsigned char *) OK, strlen(OK)) )
			goto done;
		if ( !duct->send_packet(duct, PossumPipe_data, bufr) )
			goto done;
		fputs("EDI reception complete.\n", stderr);

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
	     *err	= NULL;

	int opt,
	    retn = 1;

	pid_t pid = 0;

	PossumPipe pipe = NULL;


	fputs("EDI receiver started.\n", stdout);
	fflush(stdout);

	while ( (opt = getopt(argc, argv, "e:h:")) != EOF )
		switch ( opt ) {
			case 'e':
				engine = optarg;
				break;
			case 'h':
				host = optarg;
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


	/* Initialize process table. */
	init_process_table();

	/* Initialize the connection to the EDI engine. */
	fputs("Waiting for engine.\n", stderr);
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


	/* Initialize the network port and wait for connections. */
	INIT(NAAAIM, PossumPipe, pipe, goto done);
	if ( !pipe->init_server(pipe, host, RECEIVER_PORT, false) ) {
		fputs("Cannot set server mode.\n", stderr);
		goto done;
	}


	/* Process connections. */
	while ( 1 ) {
		fputs("Waiting for connection.\n", stderr);
		if ( !pipe->accept_connection(pipe) ) {
			err = "Error on connection accept.";
			goto done;
		}

		pid = fork();
		if ( pid == -1 ) {
			err = "Connection fork failure.";
			goto done;
		}
		if ( pid == 0 ) {
			fputs("Calling connection handler.\n", stderr);
			handle_connection(pipe);
			_exit(0);
		}

		add_process(pid);
		update_process_table();
		pipe->reset(pipe);
	}

#if 0
	fputs("Waiting for connection.\n", stderr);
	if ( !pipe->accept_connection(pipe) ) {
		err = "Error on connection accept.";
		goto done;
	}
	handle_connection(pipe);
#endif


 done:
	if ( err != NULL )
		fprintf(stderr, "!%s\n", err);

	WHACK(pipe);
	WHACK(Engine);

	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
