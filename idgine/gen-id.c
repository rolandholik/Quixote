/** \file
 *
 * This file implements a command-line client for the identity generation
 * engine.  Based on command-line arguements which are specified it
 * issues a request to the management daemon for the generation of
 * an identity.
 */

/**************************************************************************
 * (C)Copyright 2014, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/

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

#include "OrgID.h"
#include "Identity.h"
#include "IDengine.h"


/**
 * Internal private function.
 *
 * This function is used to automate input and processing of a line
 * of text from an input stream.  The linefeed in the input file, if
 * any, is converted to a NULL character.
 *
 * \param input		A pointer to the input stream to be read.
 *
 * \param bufr		A pointer to the buffer which the input line
 *			is to be read into.
 *
 * \param cnt		The maximum number of characters to bread.
 *
 * \return		A boolean value is used to indicate the status
 *			of the read.  A true value indicates the
 *			supplied buffer contains valid data.
 */

static _Bool _getline(FILE *input, char * const bufr, const size_t cnt)

{
	char *p;


	if ( fgets(bufr, cnt, input) == NULL )
		return false;
	if ( (p = strchr(bufr, '\n')) != NULL )
		*p = '\0';

	if ( strcmp(bufr, "quit") == 0 )
		return false;

	return true;
}

/**
 * Private function.
 *
 * This function is responsible for running an interactive loop to
 * request the generation of identities.  The loop is terminated by
 * entering the string 'quit' in response to any prompt.
 *
 * \return		No return value is specified.
 */

static _Bool interactive_loop(CO(IDengine, idengine), CO(String, name), \
			      CO(String, identifier), CO(Buffer, identity))

{
	_Bool retn = false;

	char inbufr[80];

	IDengine_identity idtype = IDengine_none;


	/* Get the identity type. */
	fputs("Identity type: user, device, service: user>", stdout);
	fflush(stdout);
	if ( !_getline(stdin, inbufr, sizeof(inbufr)) )
		goto done;
	if ( strlen(inbufr) == 0 )
		strcpy(inbufr, "user");
	if ( strcmp(inbufr, "user") == 0 )
		idtype = IDengine_user;
	if ( strcmp(inbufr, "device") == 0 )
		idtype = IDengine_device;
	if ( strcmp(inbufr, "service") == 0 )
		idtype = IDengine_service;

	if ( idtype == IDengine_none ) {
		fputs("Invalid identity type\n", stdout);
		goto done;
	}
		

	/* Get the identity name. */
	fprintf(stdout, "%s class name: %s1>", inbufr, inbufr);
	fflush(stdout);
	if ( !_getline(stdin, inbufr, sizeof(inbufr)) )
		goto done;

	if ( strlen(inbufr) == 0 ) {
		switch ( idtype ) {
			case IDengine_none:
				break;
			case IDengine_user:
				name->add(name, "user");
				break;
			case IDengine_device:
				name->add(name, "device");
				break;
			case IDengine_service:
				name->add(name, "service");
				break;
		}
		if ( !name->add(name, "1") )
			goto done;
	} else
		if ( !name->add(name, inbufr) )
			goto done;


	/* Get the identity identifier. */
	fprintf(stdout, "%s identifier: >", name->get(name));
	fflush(stdout);
	if ( !_getline(stdin, inbufr, sizeof(inbufr)) )
		goto done;
	if ( !identifier->add(identifier, inbufr) )
		goto done;

	if ( !idengine->get_identity(idengine, IDengine_device, name, \
				     identifier, identity) )
		goto done;
	retn = true;


 done:
	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	enum {none, interactive} mode = none;

	Buffer identity = NULL;

	String name	  = NULL,
	       identifier = NULL;

	IDengine idengine = NULL;


	/* Parse options and set mode. */
	while ( (opt = getopt(argc, argv, "I")) != EOF )
		switch ( opt ) {
			case 'I':
				mode = interactive;
				break;
		}


	INIT(HurdLib, Buffer, identity, goto done);
	INIT(HurdLib, String, name, goto done);
	INIT(HurdLib, String, identifier, goto done);

	INIT(NAAAIM, IDengine, idengine, goto done);
	if ( !idengine->attach(idengine) ) {
		fputs("Failed attach\n", stderr);
		retn = 0;
		goto done;
	}

	/* Run interactive mode. */
	if ( mode == interactive ) {
		while ( interactive_loop(idengine, name, identifier, \
					 identity) ) {
			fputs("identity: ", stdout);
			identity->print(identity);
			fputc('\n', stdout);
			fflush(stdout);

			name->reset(name);
			identifier->reset(identifier);
			identity->reset(identity);
		}
		goto done;
	}


	name->add(name, "device1");
	identifier->add(identifier, "140330001");
	if ( idengine->get_identity(idengine, IDengine_device, name, \
				    identifier, identity) ) {
		fputs("identity: ", stdout);
		identity->print(identity);
	}
	else
		fputs("Error generating identity.\n", stderr);
		

 done:
	WHACK(identity);
	WHACK(name);
	WHACK(identifier);
	WHACK(idengine);
	WHACK(identity);

	return retn;
}
