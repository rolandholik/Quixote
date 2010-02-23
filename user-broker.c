/** \file
 * This file contains an implementation of the user identity broker
 * server.   This server is responsible for arbitrating identity
 * authentication requests for a user.
 *
 * The server accepts an identity broker request which consists of
 * a user authenticator.  The authenticator is decrypted and
 * converted into an identity token.  The identity token is then used
 * to search for a match in the set of organizations managed by this
 * server.
 *
 * If a match is found the identity is decrypted and validated.  If
 * the identity is authentic and authorized the identity elements
 * are decrypted and returned to the caller.
 */

/**************************************************************************
 * (C)Copyright 2010, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define SERVER "User Authentication Broker"
#define SITE "Level 3"
#define LOCATION "Missoula, MT"

/* Include files. */
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <Config.h>
#include <Buffer.h>

#include "NAAAIM.h"
#include "Duct.h"
#include "IDtoken.h"
#include "Authenticator.h"


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
 * This function is called after a fork to handle an accepted connection.
 *
 * \param duct	The SSL connection object describing the accepted connection.
 *
 * \return	A value of zero is used to indicate the connection has
 *		been handled successfully.  A value of 1 indicates
 *		connection handling has failed.
 */

static int handle_connection(const Duct const duct)

{
	auto char banner[256];

	auto int retn = 1;

	auto Buffer bufr = NULL;

	auto Authenticator authn = NULL;

	auto IDtoken token = NULL;


	if ( (bufr = HurdLib_Buffer_Init()) == NULL )
		goto done;
	if ( (authn = NAAAIM_Authenticator_Init()) == NULL )
		goto done;
	if ( (token = NAAAIM_IDtoken_Init()) == NULL )
		goto done;
		

	/* Send the connection banner. */
	snprintf(banner, sizeof(banner), "%s / %s / %s\nHello\n", SERVER, \
		 SITE, LOCATION);
	bufr->add(bufr, (unsigned char *) banner, strlen(banner));
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;


	/* Read and process device authenticator. */
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		goto done;

	if ( !authn->decode(authn, bufr) ) {
		fputs("Failed decode.\n", stderr);
		goto done;
	}

	authn->decrypt(authn, "./org-public.pem");

	fputs("Device identity:\n", stdout);
	authn->get_identity(authn, token);
	token->print(token);


 done:
	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( authn != NULL )
		authn->whack(authn);
	if ( token != NULL )
		token->whack(token);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	auto char *config;

	auto int retn = 1;

	auto pid_t pid;

	auto Config parser = NULL;

	auto Duct duct = NULL;


	fprintf(stdout, "%s started.\n", SERVER);
	fflush(stdout);

	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "c:")) != EOF )
		switch ( retn ) {

			case 'c':
				config = optarg;
				break;
		}
	retn = 1;

	if ( config == NULL )
		config = "./root-referral.conf";


	/* Initialize process table. */
	init_process_table();


	/* Initialize SSL connection and wait for connections. */
	if ( (duct = NAAAIM_Duct_Init()) == NULL ) {
		fputs("Error on SSL object creation.\n", stderr);
		goto done;
	}

	if ( !duct->init_server(duct) ) {
		fputs("Cannot initialize server mode.\n", stderr);
		goto done;
	}

	if ( !duct->load_credentials(duct, "./org-private.pem", \
				     "./org-cert.pem") ) {
		fputs("Cannot load server credentials.\n", stderr);
		goto done;
	}

	if ( !duct->init_port(duct, NULL, 11992) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	while ( 1 ) {
		if ( !duct->accept_connection(duct) ) {
			fputs("Error on SSL connection accept.\n", stderr);
			goto done;
		}

		pid = fork();
		if ( pid == -1 ) {
			fputs("Connection fork failure.\n", stderr);
			goto done;
		}
		if ( pid == 0 ) {
			retn = handle_connection(duct);
			goto done;
		}

		fprintf(stdout, "Client connection dispatched to: %d\n", \
			pid);
		add_process(pid);
		update_process_table();
		duct->reset(duct);
	}


 done:
	if ( !duct->whack_connection(duct) )
		fputs("Error closing connection.\n", stderr);

	if ( parser != NULL )
		parser->whack(parser);
	if ( duct != NULL )
		duct->whack(duct);

	return retn;
}
