/** \file
 * This file implements a test driver for the ISOidentity modeling
 * object.  This object implements a behavior model based on an
 * execution trajectory map.
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

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include "ContourPoint.h"
#include "ExchangeEvent.h"
#include "ISOidentity.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool updated,
	      discipline,
	      forensics		= false,
	      verbose		= false,
	      dump_measurement	= false,
	      dump_events	= false,
	      dump_contours	= false,
	      dump_forensics	= false;

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
	while ( (opt = getopt(argc, argv, "CEFMa:fi:v")) != EOF )
		switch ( opt ) {
			case 'C':
				dump_contours = true;
				break;
			case 'E':
				dump_events = true;
				break;
			case 'F':
				dump_forensics = true;
				break;
			case 'M':
				dump_measurement = true;
				break;
			case 'a':
				aggregate = optarg;
				break;
			case 'f':
				forensics = true;
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

		if ( !model->update(model, event, &updated, &discipline) )
			ERR(goto done);
		if ( !updated )
			WHACK(event);
	}


	/* Register a forensics event. */
	if ( forensics ) {
		model->seal(model);

		input->reset(input);
		if ( !input->add(input, "event{sh:/bin/dotest.sh} actor{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} subject{uid=0, gid=0, mode=0100755, name_length=14, name=3bb11576b7c0dd5cf9f4308f60f8e58a07590c0c5db20859f86611c54c67013b, s_id=xvdb, s_uuid=f37070fc24894435b96e88f40a12a7c0, digest=1a3847fb368bde910be9095a52859a88faff7d0474528cadedf46f96802cc9fc}") )
			ERR(goto done);

		INIT(NAAAIM, ExchangeEvent, event, ERR(goto done));
		if ( !event->parse(event, input) ) {
			fputs("Failed to parse event:\n", stderr);
			input->print(input);
			ERR(goto done);
		}
		if ( !event->measure(event) )
			ERR(goto done);
		if ( !model->update(model, event, &updated, &discipline) )
			ERR(goto done);
		if ( !updated )
			WHACK(event);
	}


	/* Output requested model parameters. */
	if ( dump_events )
		model->dump_events(model);

	if ( dump_forensics )
		model->dump_forensics(model);

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
