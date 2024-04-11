/** \file
 * This file implements the generation of the security states represented
 * by an execution trajectory of security interaction events.  The generated
 * states represent the final state of a security domain.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <SHA256.h>

#include "SecurityEvent.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool prefix  = false,
	      verbose = false;

	char *input_file = NULL;

	int opt,
	    retn = 1;

	Buffer bufr = NULL;

	File trajectory = NULL;

	String entry = NULL;

	SecurityEvent event = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "pvi:")) != EOF )
		switch ( opt ) {
			case 'p':
				prefix = true;
				break;
			case 'v':
				verbose = true;
				break;

			case 'i':
				input_file = optarg;
				break;
		}

	if ( input_file == NULL ) {
		fputs("No trajectory file specifed.\n", stderr);
		goto done;
	}


	/* Read and process file. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));

	INIT(HurdLib, File, trajectory, ERR(goto done));
	if ( !trajectory->open_ro(trajectory, input_file) )
		ERR(goto done);

	while ( trajectory->read_String(trajectory, entry) ) {
		event->parse(event, entry);
		if ( !event->measure(event) )
			ERR(goto done);

		if ( verbose ) {
			entry->print(entry);
			fputc('\n', stdout);
			event->dump(event);
			fputc('\n', stdout);
			fputs("State: ", stdout);
		}

		bufr->reset(bufr);
		event->get_identity(event, bufr);
		if ( prefix )
			fputs("state ", stdout);
		bufr->print(bufr);
		if ( verbose)
			fputs("\n\n", stdout);

		event->reset(event);
		bufr->reset(bufr);
		entry->reset(entry);
	}
	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(event);
	WHACK(trajectory);

	return retn;
}
