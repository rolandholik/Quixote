/** \file
 *
 * This file implements a utility for managing indexes in an indexing
 * tool such as Elasticsearch or Opensearch.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "ESclient.h"


/*
 * Program entry point begins here.
 */

int main(int argc, char *argv[])

{
	char *host  = NULL,
	     *index = NULL,
	     *pwd   = NULL,
	     *user  = NULL;

	int opt,
	    rc = 1;

	enum {
		no_mode,
		list_mode
	} mode = no_mode;

	Buffer bufr = NULL;

	ESclient client = NULL;


	/* Parse and validate arguments. */
	while ( (opt = getopt(argc, argv, "Lh:i:p:u:")) != EOF )
		switch ( opt ) {
			case 'L':
				mode = list_mode;
				break;

			case 'h':
				host = optarg;
				break;
			case 'i':
				index = optarg;
				break;
			case 'p':
				pwd = optarg;
				break;
			case 'u':
				user = optarg;
				break;
		}

	if ( mode == no_mode ) {
		fputs("No mode specified.\n", stderr);
		goto done;
	}

	if ( host == NULL )
		host = getenv("QUIXOTE_IDX_HOST");
	if ( host == NULL ) {
		fputs("No host specified.\n", stderr);
		goto done;
	}

	if ( user == NULL )
		user = getenv("QUIXOTE_IDX_USER");
	if ( user == NULL ) {
		fputs("No user specified.\n", stderr);
		goto done;
	}

	if ( pwd == NULL )
		pwd = getenv("QUIXOTE_IDX_PWD");


	/* Initialize the index manipulation objects. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(NAAAIM, ESclient, client, ERR(goto done));
	if ( !client->init(client, host, index, user, pwd, bufr) )
		ERR(goto done);

	switch ( mode ) {
		case list_mode:
			if ( !client->list(client) )
				ERR(goto done);
			if ( !bufr->add(bufr, (void *) "\0", 1) )
				ERR(goto done);
			fprintf(stdout, "%s", bufr->get(bufr));
			break;

		default:
			break;
	}
	rc = 0;


 done:
	WHACK(bufr);
	WHACK(client);

	return rc;
}
