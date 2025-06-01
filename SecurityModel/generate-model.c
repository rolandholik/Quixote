/** \file
 * This file implements the generation of the security coefficients by
 * an execution trajectory as processed through a specific model.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
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

#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool updated,
	      sealed,
	      violation,
	      verbose = false;

	char *input_file = NULL;

	int opt,
	    retn = 1;

	Buffer bufr = NULL;

	File trajectory = NULL;

	String descn = NULL;

	SecurityEvent event = NULL;

	TSEM model = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "pvi:")) != EOF )
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
	INIT(HurdLib, String, descn, ERR(goto done));

	INIT(NAAAIM, TSEM, model, ERR(goto done));

	INIT(HurdLib, File, trajectory, ERR(goto done));
	if ( !trajectory->open_ro(trajectory, input_file) )
		ERR(goto done);

	while ( trajectory->read_String(trajectory, descn) ) {
		if ( verbose ) {
			descn->print(descn);
			fputc('\n', stdout);
		}

		INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
		if ( !event->parse(event, descn) )
			ERR(goto done);
		if ( !model->update(model, event, &updated, &violation, \
				    &sealed) )
			ERR(goto done);

		if ( verbose ) {
			event->dump(event);
			fputs("\nState: ", stdout);
		}

		if ( !updated ) {
			WHACK(event);
		} else {
			event->get_identity(event, bufr);
			fputs("state ", stdout);
			bufr->print(bufr);
			if ( verbose)
				fputs("\n\n", stdout);
		}

		bufr->reset(bufr);
		descn->reset(descn);
	}

	fputs("seal\n", stdout);
	fputs("end\n", stdout);
	retn = 0;


 done:
	WHACK(bufr);
	WHACK(descn);
	WHACK(event);
	WHACK(trajectory);
	WHACK(model);

	return retn;
}
