/** \file
 * This file implements a server for fielding network based identity
 * requests and requesting their resolution through a local identity
 * generator.
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

#include "Duct.h"
#include "OrgID.h"
#include "Identity.h"
#include "IDengine.h"


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
					fputs(" abnormally\n", stdout);
					continue;
				}
				fprintf(stdout, ", status = %d\n", \
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

static void handle_connection(CO(Duct,duct))

{
	pid_t pid;

	Buffer bufr = NULL;

	IDengine idengine = NULL;


	INIT(HurdLib, Buffer, bufr, goto done);

	INIT(NAAAIM, IDengine, idengine, goto done);
	if ( !idengine->attach(idengine) )
		goto done;

	fprintf(stdout, "\n.Processing identity request from %s.\n", \
		duct->get_client(duct));

	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;

	if ( !idengine->decode_get_identity(idengine, bufr) )
		goto done;

	if ( !duct->send_Buffer(duct, bufr) )
		goto done;


 done:
	WHACK(bufr);
	WHACK(idengine);

	/* Child process exits. */
	if ( pid == 0 ) {
		fputs("child process exiting.\n", stderr);
		duct->whack(duct);
		exit(0);
	}

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *err = NULL;

	int retn = 1;

	pid_t pid = 0;

	Duct duct = NULL;

 
	fputs("idsvr started.\n", stdout);
	fflush(stdout);

	/* Initialize process table. */
	init_process_table();

	/* Initialize the network port and wait for connections. */
	INIT(NAAAIM, Duct, duct, goto done);

	if ( !duct->init_server(duct) ) {
		fputs("Cannot set server mode.\n", stderr);
		goto done;
	}

	if ( !duct->set_server(duct, "127.0.0.1") ) {
		err = "Cannot set server name.";
		goto done;
	}
	
	if ( !duct->init_port(duct, NULL, 10200) ) {
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
			goto done;
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
