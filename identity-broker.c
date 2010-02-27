/** \file
 * This file contains an implementation of the identity broker
 * server.   This server is responsible for determining which organization
 * originate a patient identity.
 *
 * The server accepts an identity query request which consists of
 * two authenticator replies.  The first authenticator reply consists
 * of the set of organizational identity keys assigned to the user.
 * The second reply consists of the organizational identities assigned
 * to the user.
 *
 * The server correlates the two sets of identity elements and for
 * each pair checks to see if any of the organizational identities
 * managed by the broker yields the user organizational identity.
 */

/**************************************************************************
 * (C)Copyright 2010, Enjellic Systems Development. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define SERVER "Identity Brokerage Server"
#define SITE "Clear Lake Cooperative Telephone"
#define LOCATION "Clear Lake, SD"

#define FAILED "Authentication failed."

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
#include "AuthenReply.h"


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
 * This is a utility function which prints the contents of a text
 * buffer received from a server.
 *
 * \param bufr	The buffer object containing the text to be printed.
 */

static void print_buffer(const Buffer const bufr)

{
	auto char *p,
		  *begin,
		  pbufr[160];


	/* Sanity check. */
	if ( bufr->size(bufr) > 160 ){
		fputs(".reply too long to print", stdout);
		return;
	} 


	/*
	 * Copy the buffer and loop through it prepending a token to
	 * indicate this is an incoming response.
	 */
	memcpy(pbufr, bufr->get(bufr), bufr->size(bufr));

	begin = pbufr;
	do {
		if ( (p = strchr(begin, '\n')) != NULL ) {
			*p = '\0';
			fprintf(stdout, "<%s\n", begin);
			begin = p;
			++begin;
		}
	} while ( p != NULL );

	return;
}
			
		
/**
 * Private function.
 *
 * This function is called after a fork to handle an accepted connection.
 *
 * \param duct	The SSL connection object describing the accepted connection.
 *
 * \return	A boolean value is used to indicate the success or
 *		failure of the connection.  A true value indicates the
 *		connection has been successfully processed.
 */

static _Bool handle_connection(const Duct const duct)

{
	auto char banner[256];

	auto int retn = false;

	auto Buffer bufr = NULL;

	auto AuthenReply orgkey = NULL,
		         orgid  = NULL;


	if ( (bufr = HurdLib_Buffer_Init()) == NULL )
		goto done;

	orgkey = NAAAIM_AuthenReply_Init();
	orgid  = NAAAIM_AuthenReply_Init();
	if ( (orgkey == NULL) || (orgid == NULL) )
		goto done;
		

	/* Send the connection banner. */
	fprintf(stdout, "\n.Accepted client connection from %s.\n", \
		duct->get_client(duct));

	snprintf(banner, sizeof(banner), "%s / %s / %s\nHello\n", SERVER, \
		 SITE, LOCATION);
	bufr->add(bufr, (unsigned char *) banner, strlen(banner));
	if ( !duct->send_Buffer(duct, bufr) )
		goto done;


	/* Read the organizational key elements. */
	bufr->reset(bufr);
	fputs("<Receiving organizational key elements.\n", stdout);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("!Error receiving key elements.\n", stderr);
		goto done;
	}
	if ( !orgkey->decode(orgkey, bufr) ) {
		fputs("!Error decoding key elements.\n", stderr);
		goto done;
	}

	/* Read the organizational identity elements. */
	bufr->reset(bufr);
	fputs("<Receiving organizational identity elements.\n", stdout);
	if ( !duct->receive_Buffer(duct, bufr) ) {
		fputs("!Error receiving identity elements.\n", stderr);
		goto done;
	}
	if ( !orgid->decode(orgid, bufr) ) {
		fputs("!Error decoding identity elements.\n", stderr);
		goto done;
	}

	fputs(".elkey: ", stdout);
	orgkey->print(orgkey);
	fputs(".elid:  ", stdout);
	orgid->print(orgid);

	retn = true;


 done:
	if ( retn == false ) {
		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) FAILED, strlen(FAILED));
		if ( !duct->send_Buffer(duct, bufr) )
			goto done;
	}

	if ( bufr != NULL )
		bufr->whack(bufr);
	if ( orgkey != NULL )
		orgkey->whack(orgkey);
	if ( orgid != NULL )
		orgid->whack(orgid);

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
		config = "./identity-brokerage.conf";


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

	if ( !duct->init_port(duct, NULL, 11993) ) {
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
			if ( handle_connection(duct) ) {
				retn = 0;
				goto done;
			}
		}

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
