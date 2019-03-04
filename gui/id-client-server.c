/** \file
 * This file implements a server which receives forwarded identity
 * requests and reciprocates the identity against the local identity
 * topology.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#define IDQUERY_HOST "10.0.2.1"
#define IDQUERY_PORT 10988

#define IDSVR_HOST   "10.0.2.1"
#define IDSVR_PORT   10903

#define IDRECIP_HOST "10.0.4.1"
#define IDRECIP_PORT 10904


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

#include "SSLduct.h"
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


static void add_hex(CO(String, identifier), CO(Buffer, identity))

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

static void handle_connection(CO(SSLduct,sslduct))

{

	char *p,
	     *bp;

	IDengine_identity idtype = IDengine_none;

	String name	  = NULL,
	       identifier = NULL;

	IDengine idengine = NULL;

	Duct duct = NULL,
	     fwd  = NULL;

	Buffer identity = NULL;


	/* Receive the identity request. */
	INIT(HurdLib, Buffer, identity, goto done);
	if ( !sslduct->receive_Buffer(sslduct, identity) )
		goto done;


	/* Parse the message into type, name and identifier. */
	INIT(HurdLib, String, name, goto done);
	INIT(HurdLib, String, identifier, goto done);
	if ( !identity->add(identity, (unsigned char *) "\0", 1) )
		goto done;
	fprintf(stderr, "Identity request string: %s\n", \
		identity->get(identity));
	bp = (char *) identity->get(identity);

	if ( (p = strchr(bp, ':')) == NULL )
		goto done;
	*p = '\0';
	if ( strcmp(bp, "user") == 0 )
		idtype = IDengine_user;
	if ( strcmp(bp, "device") == 0 )
		idtype = IDengine_device;
	if ( strcmp(bp, "service") == 0 )
		idtype = IDengine_service;
	bp = p + 1;

	if ( (p = strchr(bp, ':')) == NULL )
		goto done;
	*p = '\0';
	if ( !name->add(name, bp) )
		goto done;
	bp = p + 1;

	if ( !identifier->add(identifier, bp) )
		goto done;

	fprintf(stderr, "type: %d\n", idtype);
	fputs("name: ", stderr);
	name->print(name);
	fputs("identifier: ", stderr);
	identifier->print(name);
	fputc('\n', stderr);


	/* Process identity request. */
	INIT(NAAAIM, Duct, duct, goto done);
	INIT(NAAAIM, IDengine, idengine, goto done);

	identity->reset(identity);
	if ( !idengine->encode_get_identity(idengine, idtype, name, \
					    identifier, identity) ) {
		fputs("Identity encoding failed.\n", stderr);
		goto done;
	}

	if ( !duct->init_client(duct) ) {
		fputs("Cannot initialize network client.\n", stderr);
		goto done;
	}
	if ( !duct->init_port(duct, IDSVR_HOST, IDSVR_PORT) ) {
		fputs("Cannot initiate connection.\n", stderr);
		goto done;
	}

	if ( !duct->send_Buffer(duct, identity) ) {
		fputs("Error sending buffer.\n", stderr);
		goto done;
	}

	identity->reset(identity);
	if ( !duct->receive_Buffer(duct, identity) ) {
		fputs("Error receiving buffer.\n", stderr);
		goto done;
	}

	if ( !idengine->decode_identity(idengine, identity) ) {
		fputs("Error decoding identity\n", stderr);
		goto done;
	}
#if 0
	if ( idengine->query_failed(idengine) ) {
		fputs("Local identity generation failed.\n", stderr);
		goto done;
	}
#endif


	/* Forward the identity for reciprocation. */
	fputs("Fowarding local identity:\n", stdout);
	identity->print(identity);

	identifier->reset(identifier);
	identifier->add(identifier, "Local identity:\n");
	add_hex(identifier, identity);
	identifier->add(identifier, "\n");

	INIT(NAAAIM, Duct, fwd, goto done);
	if ( !fwd->init_client(fwd) ) {
		fputs("Cannot initialize forwarding client.\n", stderr);
		goto done;
	}
	if ( !duct->init_port(duct, IDRECIP_HOST, IDRECIP_PORT) ) {
		fputs("Cannot initiate forwarding connection.\n", stderr);
		goto done;
	}

	if ( !duct->send_Buffer(duct, identity) ) {
		fputs("Error sending buffer.\n", stderr);
		goto done;
	}

	identity->reset(identity);
	if ( !duct->receive_Buffer(duct, identity) ) {
		fputs("Error receiving buffer.\n", stderr);
		goto done;
	}
	fputs("Reciprocated identity:\n", stdout);
	identity->print(identity);
	fputc('\n', stdout);

	identifier->add(identifier, "Reciprocated identity:\n");
	add_hex(identifier, identity);
	identifier->add(identifier, "\n");

	identity->reset(identity);
	identity->add(identity,					     \
		      (unsigned char *) identifier->get(identifier), \
		      identifier->size(identifier));
	sslduct->send_Buffer(sslduct, identity);


 done:
	WHACK(name);
	WHACK(identifier);
	WHACK(idengine);
	WHACK(duct);
	WHACK(fwd);
	WHACK(identity);
		
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

	if ( !duct->load_credentials(duct, "/etc/server-private.pem", \
				     "/etc/server-cert.pem") ) {
		fputs("Cannot load credentials.\n", stderr);
	}

	
	if ( !duct->init_port(duct, NULL, IDQUERY_PORT) ) {
		fputs("Cannot initialize port.\n", stderr);
		goto done;
	}

	while ( 1 ) {
		fputs("Waiting for connection.\n", stderr);
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
