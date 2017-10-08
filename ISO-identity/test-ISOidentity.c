/** \file
 * This file implements a test driver for the ISOidentity modeling
 * object.  This object implements a behavior model based on an
 * execution trajectory map.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include "ExchangeEvent.h"
#include "ISOidentity.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool updated,
	      verbose		= false,
	      dump_measurement	= false,
	      dump_events	= false,
	      dump_contours	= false;

	char *aggregate  = NULL,
	     *trajectory = NULL;

	int opt,
	    retn = 1;

	Buffer bufr = NULL;

	File infile = NULL;

	String input = NULL;

	ExchangeEvent event = NULL;

	ISOidentity model = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "CEMa:i:v")) != EOF )
		switch ( opt ) {
			case 'C':
				dump_contours = true;
				break;
			case 'E':
				dump_events = true;
				break;
			case 'M':
				dump_measurement = true;
				break;
			case 'a':
				aggregate = optarg;
				break;
			case 'i':
				trajectory = optarg;
				break;
			case 'v':
				verbose = true;
				break;
		}


	/* Open the trajectory file. */
	if ( trajectory == NULL ) {
		fputs("No trajectory file specified.\n", stderr);
		goto done;
	}

	INIT(HurdLib, File, infile, ERR(goto done));
	if ( !infile->open_ro(infile, trajectory) )
		ERR(goto done);


	/* Set the aggregate value for the behavioral model. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, ISOidentity, model, ERR(goto done));
	if ( aggregate != NULL ) {
		if ( strlen(aggregate) != NAAAIM_IDSIZE*2 ) {
			fputs("Invalid aggregate value.\n", stderr);
			goto done;
		}
		if ( !bufr->add_hexstring(bufr, aggregate) )
			ERR(goto done);
		if ( !model->set_aggregate(model, bufr) )
			ERR(goto done);
		bufr->reset(bufr);
	}


	/* Process the trajectory file. */
	INIT(HurdLib, String, input, ERR(goto done));

	while ( infile->read_String(infile, input) ) {
		INIT(NAAAIM, ExchangeEvent, event, ERR(goto done));
		if ( !event->parse(event, input) ) {
			fputs("Failed to parse event:\n", stderr);
			input->print(input);
			ERR(goto done);
		}
		input->reset(input);

		if ( !event->measure(event) )
			ERR(goto done);

		if ( !model->update(model, event, &updated) )
			ERR(goto done);
		if ( !updated )
			WHACK(event);
	}

	if ( dump_events )
		model->dump_events(model);
	if ( dump_contours ) {
		if ( verbose )
			fputs("Contours:\n", stdout);
		model->dump_contours(model);
	}
	if ( dump_measurement ) {
		if ( verbose )
			fputs("Measurement:\n", stdout);
		if ( !model->get_measurement(model, bufr) )
			ERR(goto done);
		bufr->print(bufr);
	}

	retn = 0;

 done:
	WHACK(bufr);
	WHACK(input);
	WHACK(infile);
	WHACK(model);

	return retn;
}
