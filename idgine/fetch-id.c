/** \file
 *
 * This file implements a command-line client for executing a network
 * based identity request.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

/* Local defines. */
#define IDSVR_PORT 10903


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "Duct.h"
#include "OrgID.h"
#include "Identity.h"
#include "IDengine.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	char *type = NULL;

	IDengine_identity idtype = IDengine_none;

	Buffer identity = NULL;

	String host = NULL,
	       name = NULL,
	       identifier = NULL;

	IDengine idengine = NULL;

	Duct duct = NULL;


	/* Parse options and set mode. */
	INIT(HurdLib, String, host, goto done);
	INIT(HurdLib, String, name, goto done);
	INIT(HurdLib, String, identifier, goto done);

	while ( (opt = getopt(argc, argv, "h:i:n:t:")) != EOF )
		switch ( opt ) {
			case 'h':
				if ( !host->add(host, optarg) )
					goto done;
				break;

			case 'i':
				if ( !identifier->add(identifier, optarg) )
					goto done;
				break;

			case 'n':
				if ( !name->add(name, optarg) )
					goto done;
				break;

			case 't':
				type = optarg;
				break;
		}

	/* Set identity type. */
	if ( type == NULL ) {
		fputs("No identity type specified.\n", stderr);
		goto done;
	}
	if ( strcmp(type, "user") == 0 )
		idtype = IDengine_user;
	if ( strcmp(type, "device") == 0 )
		idtype = IDengine_device;
	if ( strcmp(type, "service") == 0 )
		idtype = IDengine_service;

	/* Verify host and identity parameters. */
	if ( host->size(host) == 0 ) {
		fputs("No hostname specifed.\n", stderr);
		goto done;
	}
	if ( name->size(name) == 0 ) {
		fputs("No identity name specified.\n", stderr);
		goto done;
	}
	if ( identifier->size(identifier) == 0 ) {
		fputs("No identifier specified.\n", stderr);
		goto done;
	}

	/* Process identity request. */
	INIT(HurdLib, Buffer, identity, goto done);
	INIT(NAAAIM, Duct, duct, goto done);

	INIT(NAAAIM, IDengine, idengine, goto done);
	if ( !idengine->encode_get_identity(idengine, idtype, name, \
					    identifier, identity) ) {
		fputs("Identity encoding failed.\n", stderr);
		goto done;
	}

	if ( !duct->init_client(duct) ) {
		fputs("Cannot initialize network client.\n", stderr);
		goto done;
	}
	if ( !duct->init_port(duct, host->get(host), IDSVR_PORT) ) {
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

	fputs("identity: ", stdout);
	identity->print(identity);

	retn = 0;
		

 done:
	WHACK(host);
	WHACK(name);
	WHACK(identifier);
	WHACK(identity);
	WHACK(idengine);
	WHACK(duct);

	return retn;
}
