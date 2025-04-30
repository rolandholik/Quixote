/** \file
 *
 * This file implements a utility for injecting documents into an
 * Elasticsearch index.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "ESclient.h"


/*
 * Program entry point begins here.
 */

int main(int argc, char *argv[])

{
	char *host = NULL,
	     *index = NULL,
	     *user = NULL;

	int opt,
	    rc = 1;

	unsigned int cnt = 0;

	String str = NULL;

	File infile = NULL;

	ESclient es = NULL;


	/* Parse and validate arguments. */
	while ( (opt = getopt(argc, argv, "h:i:u:")) != EOF )
		switch ( opt ) {
			case 'h':
				host = optarg;
				break;

			case 'i':
				index = optarg;
				break;

			case 'u':
				user = optarg;
				break;
		}

	if ( host == NULL ) {
		fputs("No endpoint host specified.\n", stderr);
		return 1;
	}
	if ( index == NULL ) {
		fputs("No endpoint index specified.\n", stderr);
		return 1;
	}
	if ( user == NULL ) {
		fputs("No user name specified.\n", stderr);
		return 1;
	}


	/* Setup input string and file. */
	INIT(HurdLib, String, str, ERR(goto done));

	INIT(HurdLib, File, infile, ERR(goto done));
	if ( !infile->open_ro(infile, "/dev/stdin") ) {
		fputs("Error opening input file.\n", stderr);
		ERR(goto done);
	}

	/* Initialize the endpoint. */
	INIT(NAAAIM, ESclient, es, ERR(goto done));
	if ( !es->init(es, host, index, user, NULL) ) {
		fputs("Error initializing endpoint connection.\n", stderr);
		goto done;
	}

	/* Loop over the input and inject events. */
	while ( infile->read_String(infile, str) ) {
		if ( !es->inject(es, str) )
			ERR(goto done);
		fprintf(stdout, "Injected: %u\n", ++cnt);
		fflush(stdout);
		str->reset(str);
	}


 done:
	WHACK(str);
	WHACK(infile);
	WHACK(es);

	return rc;
}
