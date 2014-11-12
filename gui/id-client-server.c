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
#define IDQUERY_HOST "10.0.2.1"
#define IDQUERY_PORT 10988


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

#include "SSLduct.h"


/* Variables static to this module. */
static pid_t process_table[100];


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
 * \param duct	The network connection object being used to handle
 *		the identity generation request.
 *
 * \return	No return value is defined.
 */

static void handle_connection(CO(SSLduct,duct))

{
	char *id = "dd5fa01a73b3a365bf677f5819c7fbdd3ea85e4d437e93d7ccd12cd84a889e50";

	Buffer identity = NULL;


	/* Receive the identity request. */
	INIT(HurdLib, Buffer, identity, goto done);
	if ( !duct->receive_Buffer(duct, identity) )
		goto done;

	fputs("Identity request received.\n", stdout);
	identity->hprint(identity);

	identity->reset(identity);
	identity->add(identity, (unsigned char *) id, strlen(id));
	duct->send_Buffer(duct, identity);


 done:
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

	SSLduct duct = NULL;

 
	fputs("Identity query server started.\n", stdout);
	fflush(stdout);

	while ( (opt = getopt(argc, argv, "h:")) != EOF )
		switch ( opt ) {
			case 'h':
				host = optarg;
				break;
		}

	/* Arguement verification. */
#if 0
	if ( host == NULL ) {
		fputs("No hostname specified.\n", stderr);
		goto done;
	}
#endif

	/* Initialize process table. */
	init_process_table();

	/* Initialize the network port and wait for connections. */
	if ( (duct = SSLduct_Init()) == NULL ) {
		fputs("Error on SSL object creation.", stderr);
		goto done;
	}

	if ( !duct->init_server(duct) ) {
		fputs("Cannot set server mode.\n", stderr);
		goto done;
	}

	if ( !duct->load_credentials(duct, "./server-private.pem", \
				     "./server-cert.pem") ) {
		fputs("Cannot load credentials.\n", stderr);
	}

	
	if ( !duct->init_port(duct, NULL, IDQUERY_PORT) ) {
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
