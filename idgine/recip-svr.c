/** \file
 * This file implements a server which receives forwarded identity
 * requests and reciprocates the identity against the local identity
 * topology.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define IDRECIP_PORT 10904

#define IDSVR_HOST "10.0.2.1"
#define IDSVR_PORT 10903


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

#include "Duct.h"
#include "OrgID.h"
#include "Identity.h"
#include "IDengine.h"


/* Variables static to this module. */
static pid_t process_table[100];

/* Number of reciprocation requests. */
static uint32_t Recip_Count = 0;


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
				fprintf(stdout, ", status=%d", \
					WEXITSTATUS(status));
				if ( status == 0 )
					fprintf(stdout, ", Reciprocation " \
						"count: %u\n", ++Recip_Count);
				else
					fputc('\n', stdout);
			}
	return;
}


/**
 * Private function.
 *
 * This function converts an identity in binary form into its 
 * hexadecimal equivalent.
 *
 * \param identifier	The String object which will hold the
 *			ASCII ersion of the identity.
 *
 * \param identity	The Buffer object containing the identity to
 *			be encoded.
 *
 * \return		No return value is defined.
 */

static void add_identity(CO(String, identifier), CO(Buffer, identity))

{
	uint16_t lp,
		 idsize;

	char bufr[3];

	unsigned char *p;


	p      = identity->get(identity);
	idsize = identity->size(identity);

        for (lp= 0; lp < idsize; ++lp) {
                snprintf(bufr, sizeof(bufr), "%02x", *p);
                identifier->add(identifier, bufr);
		++p;
        }

	memset(bufr, '\0', sizeof(bufr));
	return;
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
	IDengine_identity idtype = IDengine_none;

	Buffer identity = NULL;

	String name	  = NULL,
	       identifier = NULL;

	IDengine idengine = NULL;

	Duct idsvr_duct = NULL;


	/* Receive the identity request. */
	INIT(HurdLib, Buffer, identity, goto done);
	if ( !duct->receive_Buffer(duct, identity) )
		goto done;

	fprintf(stdout, "\n.%d: Identity reciprocation request from %s.\n", \
		getpid(), duct->get_client(duct));
	identity->print(identity);


	/* Issue a reciprocation request to the local identity generator. */
	INIT(NAAAIM, IDengine, idengine, goto done);
	INIT(NAAAIM, Duct, idsvr_duct, goto done);
	INIT(HurdLib, String, name, goto done);
	INIT(HurdLib, String, identifier, goto done);

	if ( !idsvr_duct->init_client(idsvr_duct) ) {
		fputs("Cannot initialize network client.\n", stderr);
		goto done;
	}
	if ( !idsvr_duct->init_port(idsvr_duct, IDSVR_HOST, IDSVR_PORT) ) {
		fputs("Cannot initiate connection.\n", stderr);
		goto done;
	}


	/* Setup the identity reciprocation request. */
	idtype = IDengine_service;
	if ( !name->add(name, "service1") )
		goto done;
	add_identity(identifier, identity);

	identity->reset(identity);
	if ( !idengine->encode_get_identity(idengine, idtype, name, \
					    identifier, identity) ) {
		fputs("Identity encoding failed.\n", stderr);
		goto done;
	}


	/* Send and receive the identity reciprocation request. */
	if ( !idsvr_duct->send_Buffer(idsvr_duct, identity) ) {
		fputs("Error sending buffer.\n", stderr);
		goto done;
	}

	identity->reset(identity);
	if ( !idsvr_duct->receive_Buffer(idsvr_duct, identity) ) {
		fputs("Error receiving buffer.\n", stderr);
		goto done;
	}

	if ( !idengine->decode_identity(idengine, identity) ) {
		fputs("Error decoding identity.\n", stderr);
		goto done;
	}

	fputs("Reciprocated identity:\n", stdout);
	identity->print(identity);

	if ( !duct->send_Buffer(duct, identity) ) {
		fputs("Error returning reciprocated identity.\n", stderr);
		goto done;
	}


 done:
	WHACK(identity);
	WHACK(idengine);
	WHACK(idsvr_duct);

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *host = NULL,
	     *err  = NULL;

	int opt,
	    retn = 1;

	pid_t pid = 0;

	Duct duct = NULL;

 
	fputs("Identity reciprocation server started.\n", stdout);
	fflush(stdout);

	while ( (opt = getopt(argc, argv, "h:")) != EOF )
		switch ( opt ) {
			case 'h':
				host = optarg;
				break;
		}

	/* Arguement verification. */
	if ( host == NULL ) {
		fputs("No hostname specified.\n", stderr);
		goto done;
	}

	/* Initialize process table. */
	init_process_table();

	/* Initialize the network port and wait for connections. */
	INIT(NAAAIM, Duct, duct, goto done);

	if ( !duct->init_server(duct) ) {
		fputs("Cannot set server mode.\n", stderr);
		goto done;
	}

	if ( !duct->set_server(duct, host) ) {
		err = "Cannot set server name.";
		goto done;
	}
	
	if ( !duct->init_port(duct, NULL, IDRECIP_PORT) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	while ( 1 ) {
		if ( !duct->accept_connection(duct) ) {
			err = "Error on connection accept.";
			goto done;
		}

		pid = fork();
		if ( pid == -1 ) {
			err = "Connection fork failure.";
			goto done;
		}
		if ( pid == 0 ) {
			handle_connection(duct);
			_exit(0);
		}

		add_process(pid);
		update_process_table();
		duct->reset(duct);
	}


 done:
	if ( err != NULL )
		fprintf(stderr, "!%s\n", err);

	if ( duct != NULL ) {
	     if ( !duct->whack_connection(duct) )
		     fputs("Error closing duct connection.\n", stderr);
	     duct->whack(duct);
	}
	
	if ( pid == 0 )
		fputs(".Client terminated.\n", stdout);

	return retn;
}
