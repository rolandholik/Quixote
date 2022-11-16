/** \file
 * This file implements the display of a security execution trajectory.
 * It allows generically modeled events to be displayed with their
 * security event name rather than numeric type.
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
	_Bool generic = false,
	      verbose = false;

	char *input_file = NULL;

	int opt,
	    retn = 1;
	File trajectory = NULL;

	String entry = NULL;

	SecurityEvent event = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "gvi:")) != EOF )
		switch ( opt ) {
			case 'g':
				generic = true;
				break;
			case 'v':
				verbose = true;
				break;

			case 'i':
				input_file = optarg;
				break;
		}

	if ( input_file == NULL )
		input_file = "/dev/stdin";

	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));

	INIT(HurdLib, File, trajectory, ERR(goto done));
	if ( !trajectory->open_ro(trajectory, input_file) )
		ERR(goto done);

	while ( trajectory->read_String(trajectory, entry) ) {
		event->parse(event, entry);

		if ( verbose ) {
			entry->print(entry);
			fputc('\n', stdout);
			event->dump(event);
			fputc('\n', stdout);
		} else {
			entry->reset(entry);
			if ( generic )
				event->format_generic(event, entry);
			else
				event->format(event, entry);
			entry->print(entry);
		}

		event->reset(event);
		entry->reset(entry);
	}
	retn = 0;


 done:
	WHACK(entry);
	WHACK(event);
	WHACK(trajectory);

	return retn;
}
