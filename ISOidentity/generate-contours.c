/** \file
 * This file implements tracing of an execution trajectory path to
 * generate a behavioral contour map of the final state of the
 * modeled system.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
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

#include "ExchangeEvent.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool verbose = false;

	char *input_file = NULL;

	int opt,
	    retn = 1;

	Buffer bufr = NULL;

	File trajectory = NULL;

	String entry = NULL;

	ExchangeEvent event = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "vi:")) != EOF )
		switch ( opt ) {
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

	INIT(NAAAIM, ExchangeEvent, event, ERR(goto done));

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
			fputs("Contour: ", stdout);
		}

		bufr->reset(bufr);
		event->get_identity(event, bufr);
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
