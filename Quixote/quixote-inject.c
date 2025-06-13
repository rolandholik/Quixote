/** \file
 *
 * This file implements a utility for injecting documents into an
 * Elasticsearch (ES) index.
 *
 * The utility can either inject the raw security event descriptions
 * into an index or it can process the events through a TSEM model and
 * inject descriptions, and their associated coefficients, into an
 * index with an indication of whether or not the event description
 * describes an invalid or valid event.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"
#include "ESclient.h"
#include "SecurityEvent.h"
#include "SecurityPoint.h"
#include "TSEM.h"
#include "TSEMevent.h"
#include "TSEMparser.h"

/**
 * A boolean variable used to indicate if the model is sealed.
 */
static _Bool Sealed = false;

/**
 * The object that will be used to parse the event description.
 */
static TSEMevent Event = NULL;

/**
 * The object implementing the model.
 */
static TSEM Model = NULL;


/**
 * Private helper function.
 *
 * This function is a helper function for the setup_model function
 * and is responsible for loading a security model description into
 * the model.
 *
 * \param model_file	A pointer to a null-terminate character buffer
 *			containing the name of the file containing the
 *			model to be loaded.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the model was loaded.  A false value
 *			indicates the load of the model failed while
 *			a true value indicates the model was successfully
 *			loaded.
 */

static _Bool _load_model(CO(char *, model_file))

{
	_Bool retn = false;

	String str = NULL;

	File model = NULL;


	/* Open the behavioral map and initialize the binary point object. */
	INIT(HurdLib, String, str, ERR(goto done));

	INIT(HurdLib, File, model, ERR(goto done));
	if ( !model->open_ro(model, model_file) )
		ERR(goto done);


	/* Loop over the model file. */
	while ( model->read_String(model, str) ) {
		if ( strcmp(str->get(str), "seal") == 0 )
			Sealed = true;

		if ( !Model->load(Model, str) )
			ERR(goto done);
		str->reset(str);
	}

	retn = true;


 done:
	WHACK(str);
	WHACK(model);

	return retn;
}


/**
 * Private function.
 *
 * This function creates the model object and loads the specified model
 * if one is specified.
 *
 * \param model		A pointer to a null-terminated character buffer
 *			containing the name of the file containing a
 *			security model that the event description stream
 *			is to be referenced against.
 *
 * \return	A boolean value is returned to indicate the status of
 *		the model setup.  A false value indicates that an error
 *		occurred while a true value indicates that the model has
 *		been initialized and configured.
 */

static _Bool setup_model(CO(char *, model))

{
	_Bool retn = false;


	INIT(NAAAIM, TSEM, Model, ERR(goto done));
	INIT(NAAAIM, TSEMevent, Event, ERR(goto done));

	if ( model != NULL ) {
		if ( !_load_model(model) )
			ERR(goto done);
	}
	retn = true;


 done:
	return retn;
}


/**
 * Private function.
 *
 * This function injects a security event that has been read into a
 * TSEM model and updates the export description with the event
 * coefficient and status.
 *
 * \param str		The object containing the event description
 *			string.
 *
 * \return	A boolean value is returned to indicate the status of
 *		modeling of the event.  A false value indicates an error
 *		occurred while a true value indicates that the event
 *		has been modeled and the event description has been
 *		updated.
 */

static _Bool model_event(CO(String, str))

{
	_Bool updated,
	      violation,
	      sealed,
	      retn = false;

	char *p,
	     *type;

	unsigned char *p1;

	unsigned int lp;

	size_t size;

	Buffer bufr = NULL;

	String save = NULL;

	SecurityEvent event = NULL;


	/* Parse the event. */
	INIT(HurdLib, String, save, ERR(goto done));
	if ( !save->add(save, str->get(str)) )
		ERR(goto done);

	INIT(NAAAIM, SecurityEvent, event, ERR(goto done));
	if ( !event->parse(event, str) )
		ERR(goto done);

	/* Model the event. */
	if ( !Model->update(Model, event, &updated, &violation, &sealed) )
		ERR(goto done);

	if ( !updated )
		str->reset(str);
	else {
		if ( (p = strchr(save->get(save), '}')) == NULL )
			ERR(goto done);
		*p = '\0';

		str->reset(str);
		if ( !str->add_sprintf(str, "%s, \"coefficient\": \"", \
				       save->get(save)) )
			ERR(goto done);
		*p = '}';

		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		if ( !event->get_identity(event, bufr) )
			ERR(goto done);

		p1 = bufr->get(bufr);
		size = bufr->size(bufr);
		for (lp= 0; lp < size; ++lp) {
			if ( !str->add_sprintf(str, "%02x", *p1) )
				ERR(goto done);
			++p1;
		}

		type = violation && sealed ? "yes" : "no";
		if ( !str->add_sprintf(str, "\", \"violation\": \"%s\"", \
				       type) )
			ERR(goto done);

		if ( !str->add(str, p) )
			ERR(goto done);
	}

	retn = true;


 done:
	if ( !updated )
		WHACK(event);

	WHACK(bufr);
	WHACK(save);

	return retn;
}


/*
 * Program entry point begins here.
 */

int main(int argc, char *argv[])

{
	_Bool inject   = true,
	      modeling = false,
	      verbose  = false;

	char *host  = NULL,
	     *index = NULL,
	     *user  = NULL,
	     *model = NULL;

	int opt,
	    rc = 1;

	String str = NULL;

	File infile = NULL;

	ESclient es = NULL;


	/* Parse and validate arguments. */
	while ( (opt = getopt(argc, argv, "Mvnh:i:m:u:")) != EOF )
		switch ( opt ) {
			case 'M':
				modeling = true;
				break;

			case 'n':
				inject = false;
				break;
			case 'v':
				verbose = true;
				break;

			case 'h':
				host = optarg;
				break;
			case 'i':
				index = optarg;
				break;
			case 'm':
				model = optarg;
				break;
			case 'u':
				user = optarg;
				break;
		}


	/* Validate required inputs. */
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

	/* Open the input file. */
	INIT(HurdLib, String, str, ERR(goto done));

	INIT(HurdLib, File, infile, ERR(goto done));
	if ( !infile->open_ro(infile, "/dev/stdin") ) {
		fputs("Error opening input file.\n", stderr);
		ERR(goto done);
	}

	/* Initialize the endpoint. */
	INIT(NAAAIM, ESclient, es, ERR(goto done));
	if ( !es->init(es, host, index, user, NULL, NULL) ) {
		fputs("Error initializing endpoint connection.\n", stderr);
		goto done;
	}

	/* Initialize the model if we are running in model mode. */
	if ( modeling ) {
		if ( !setup_model(model) ) {
			fputs("Error setting up model.\n", stderr);
			goto done;
		}
	}

	/* Loop over the input and inject events. */
	while ( infile->read_String(infile, str) ) {
		if ( modeling ) {
			if ( !model_event(str) )
				ERR(goto done);
		}

		if ( str->size(str) > 0 ) {
			if ( verbose )
				str->print(str);
			if ( inject ) {
				if ( !es->inject(es, str) )
					ERR(goto done);
			}
			str->reset(str);
		}
	}


 done:
	WHACK(str);
	WHACK(infile);
	WHACK(es);

	WHACK(Event);
	WHACK(Model);

	return rc;
}
