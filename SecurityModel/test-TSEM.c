/** \file
 * This file implements a test driver for the ISOidentity modeling
 * object.  This object implements a behavior model based on an
 * execution trajectory map.
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

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include "SecurityPoint.h"
#include "SecurityEvent.h"
#include "TSEM.h"


/**
 * Private function.
 *
 * This function tests the loading of an security map into a model.
 *
 * \param model_input	The name of the file containing the model
 *			to be loaded.
 *
 * \return		This function exits the process if an
 *			error is encountered.
 */

static void model_load(CO(TSEM, model), CO(char *, model_input))

{
	_Bool retn = false;

	String str = NULL;

	File model_file = NULL;


	/* Open the file containing the model to be loaded. */
	INIT(HurdLib, File, model_file, ERR(goto done));
	if ( !model_file->open_ro(model_file, model_input) ) {
		fputs("Cannot open model file.\n", stderr);
		goto done;
	}


	/* Load the model components into the model. */
	INIT(HurdLib, String, str, ERR(goto done));

	while ( model_file->read_String(model_file, str) ) {
		if ( !model->load(model, str) ) {
			fputs("Failed model element load: %s", stdout);
			str->print(str);
			goto done;
		}
		str->reset(str);
	}

	retn = true;


 done:
	WHACK(str);
	WHACK(model_file);

	if ( !retn )
		exit(1);

	return;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool updated,
	      discipline,
	      sealed,
	      forensics		= false,
	      verbose		= false,
	      dump_measurement	= false,
	      dump_state	= false,
	      dump_events	= false,
	      dump_points	= false,
	      dump_forensics	= false,
	      load_model	= false;

	char *aggregate  = NULL,
	     *trajectory = NULL,
	     *model_file = NULL;

	int opt,
	    retn = 1;

	Buffer bufr = NULL;

	File infile = NULL;

	String input = NULL;

	SecurityEvent event = NULL;

	TSEM model = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "CEFLMSa:fm:i:v")) != EOF )
		switch ( opt ) {
			case 'C':
				dump_points = true;
				break;
			case 'E':
				dump_events = true;
				break;
			case 'F':
				dump_forensics = true;
				break;
			case 'L':
				load_model = true;
				break;
			case 'M':
				dump_measurement = true;
				break;
			case 'S':
				dump_state = true;
				break;
			case 'a':
				aggregate = optarg;
				break;
			case 'f':
				forensics = true;
				break;
			case 'm':
				model_file = optarg;
				break;
			case 'i':
				trajectory = optarg;
				break;
			case 'v':
				verbose = true;
				break;
		}


	/* Initialize the model to be used. */
	INIT(NAAAIM, TSEM, model, ERR(goto done));


	/* Test model loading. */
	if ( load_model ) {
		model_load(model, model_file);
		goto done;
	}


	/* Open the trajectory file. */
	if ( !load_model && trajectory == NULL ) {
		fputs("No trajectory file specified.\n", stderr);
		goto done;
	}

	INIT(HurdLib, File, infile, ERR(goto done));
	if ( !infile->open_ro(infile, trajectory) )
		ERR(goto done);


	/* Set the aggregate value for the behavioral model. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
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
		INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
		if ( !event->parse(event, input) ) {
			fputs("Failed to parse event:\n", stderr);
			input->print(input);
			ERR(goto done);
		}
		input->reset(input);

		if ( !model->update(model, event, &updated, &discipline, \
				    &sealed) )
			ERR(goto done);
		if ( !updated )
			WHACK(event);
	}


	/* Register a forensics event. */
	if ( forensics ) {
		model->seal(model);

		input->reset(input);
		if ( !input->add(input, "event{sh:/bin/dotest.sh} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} cell{uid=0, gid=0, mode=0100755, name_length=14, name=3bb11576b7c0dd5cf9f4308f60f8e58a07590c0c5db20859f86611c54c67013b, s_id=xvdb, s_uuid=f37070fc24894435b96e88f40a12a7c0, digest=1a3847fb368bde910be9095a52859a88faff7d0474528cadedf46f96802cc9fc}") )
			ERR(goto done);

		INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
		if ( !event->parse(event, input) ) {
			fputs("Failed to parse event:\n", stderr);
			input->print(input);
			ERR(goto done);
		}
		if ( !event->measure(event) )
			ERR(goto done);
		if ( !model->update(model, event, &updated, &discipline, \
				    &sealed) )
			ERR(goto done);
		if ( !updated )
			WHACK(event);
	}


	/* Output requested model parameters. */
	if ( dump_events )
		model->dump_events(model);

	if ( dump_forensics )
		model->dump_forensics(model);

	if ( dump_points ) {
		if ( verbose )
			fputs("Points:\n", stdout);
		model->dump_points(model);
	}

	if ( dump_measurement ) {
		if ( verbose )
			fputs("Measurement:\n", stdout);
		if ( !model->get_measurement(model, bufr) )
			ERR(goto done);
		bufr->print(bufr);
	}

	if ( dump_state ) {
		if ( verbose )
			fputs("State:\n", stdout);
		bufr->reset(bufr);
		if ( !model->get_state(model, bufr) )
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
