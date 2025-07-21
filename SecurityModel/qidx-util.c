/** \file
 *
 * This file implements a utility for managing indexes in an indexing
 * tool such as Elasticsearch or Opensearch.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>

#include "NAAAIM.h"
#include "ESclient.h"
#include "JSONparser.h"


/**
 * Internal helper function.
 *
 * This function is a helper function for the dump_index function.  It
 * outputs a set of security event descriptions held in a parser
 * array.
 *
 * \param parser	The parser object that contains an array of
 *			descriptions to be output.
 *
 * \param str		The object that will be used to extract and
 *			print each member of the array.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the output of the array succeeded.  A
 *			true value indicates the contents was dumped
 *			while a false value indicates an error occurred.
 */

static _Bool _dump_array(CO(JSONparser, parser), CO(String, str))

{
	_Bool retn = false;

	int lp,
	    cnt;


	if ( !parser->get_array_size(parser, &cnt) )
		ERR(goto done);

	for (lp= 0; lp < cnt; ++lp) {
		if ( !parser->select_array_object(parser, lp) )
			ERR(goto done);
		if ( !parser->select_object(parser, "_source") )
			ERR(goto done);

		str->reset(str);
		if ( !parser->get_object_String(parser, str) )
			ERR(goto done);
		str->print(str);
	}
	retn = true;


 done:
	return retn;
}


/**
 * Internal helper function.
 *
 * This function is a helper function that executes a scroll cycle.
 *
 * \param client	The object describing that endpoint that is
 *			being scrolled.

 * \param parser	The parser object that will be used to parse
 *			the output of the scroll transaction.
 *
 * \param bufr		The object that will contain the output of
 *			the scroll transaction.
 *
 * \param str		The object that will be used to extract the
 *			scroll id.
 *
 * \param scroll	The object that will be used to create the
 *			scroll command.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the the scroll succeeded.  A true value
 *			indicates that the scroll cycle was successfully
 *			completed while a false value indicates an
 *			error was encountered.
 */

static _Bool _scroll(CO(ESclient, client), CO(JSONparser, parser), \
		     CO(Buffer, bufr), CO(String, str), CO(String, scroll))

{
	_Bool retn = false;


	if ( !scroll->add_sprintf(scroll, "{\"scroll\": \"30s\", ") )
		ERR(goto done);
	if ( !scroll->add_sprintf(scroll, "\"scroll_id\": \"%s\"}", \
				  str->get(str)) )
		ERR(goto done);

	bufr->reset(bufr);
	if ( !client->next(client, scroll) )
		ERR(goto done);

	parser->reset(parser);
	if ( !parser->parse_Buffer(parser, bufr) )
		ERR(goto done);
	if ( !parser->select_object(parser, "hits") )
		ERR(goto done);
	if ( !parser->select_array(parser, "hits") )
		ERR(goto done);

	if ( !_dump_array(parser, str) )
		ERR(goto done);

	str->reset(str);
	parser->clear(parser);
	if ( !parser->select_string(parser, "_scroll_id") )
		ERR(goto done);
	if ( !parser->get_String(parser, str) )
		ERR(goto done);
	retn = true;


 done:
	return retn;
}


/**
 * Internal private function.
 *
 * This function outputs the documents contained in an index using the
 * scroll API.
 *
 * \param client	The index client that is to be dumped.
 *
 * \param bufr		The object that will contain the output from
 *			exchanges with the document index engine.
 *
 * \return		A boolean value is returned to indicate whether
 *			or not the .  A false value
 *			indicates a parsing error while a true value
 *			indicates the structure pointed to by the fp
 *			argument was properly populated.
 */

static _Bool dump_index(CO(ESclient, client), CO(Buffer, bufr))

{
	_Bool retn = false;

	unsigned int lp;

	int total, cnt, cycles, residual;

	String str    = NULL,
	       scroll = NULL;

	JSONparser parser = NULL;


	INIT(HurdLib, String, str, ERR(goto done));
	if ( !str->add(str, "{\"size\": 100, ") )
		ERR(goto done);
	if ( !str->add(str, "\"query\": {\"match_all\": {}}}") )
		ERR(goto done);
	if ( !client->scroll(client, str) )
		ERR(goto done);

	INIT(NAAAIM, JSONparser, parser, ERR(goto done));
	if ( !parser->parse_Buffer(parser, bufr) )
		ERR(goto done);

	parser->clear(parser);
	if ( !parser->select_object(parser, "hits") )
		ERR(goto done);

	if ( !parser->select_array(parser, "hits") )
		ERR(goto done);

	if ( !parser->select_object(parser, "total") )
		ERR(goto done);
	if ( !parser->select_integer(parser, "value") )
		ERR(goto done);
	if ( !parser->get_integer(parser, &total) )
		ERR(goto done);

	if ( !_dump_array(parser, str) )
		ERR(goto done);

	if ( !parser->get_array_size(parser, &cnt) )
		ERR(goto done);
	if ( cnt == total ) {
		retn = true;
		goto done;
	}

	/* Scroll through the remaining entries. */
	total	-= cnt;
	cycles	 = total / 100;
	residual = total % 100;

	str->reset(str);
	parser->clear(parser);
	if ( !parser->select_string(parser, "_scroll_id") )
		ERR(goto done);
	if ( !parser->get_String(parser, str) )
		ERR(goto done);

	INIT(HurdLib, String, scroll, ERR(goto done));

	for (lp= 0; lp < cycles; ++lp) {
		if ( !_scroll(client, parser, bufr, str, scroll) )
			ERR(goto done);
	}

	if ( residual != 0 ) {
		if ( !_scroll(client, parser, bufr, str, scroll) )
			ERR(goto done);
	}
	retn = true;


 done:
	WHACK(str);
	WHACK(scroll);
	WHACK(parser);

	return retn;
}


/*
 * Program entry point begins here.
 */

int main(int argc, char *argv[])

{
	char *host  = NULL,
	     *port  = NULL,
	     *index = NULL,
	     *pwd   = NULL,
	     *user  = NULL;

	int opt,
	    rc = 1;

	enum {
		no_mode,
		list_mode,
		dump_mode
	} mode = no_mode;

	Buffer bufr = NULL;

	ESclient client = NULL;


	/* Parse and validate arguments. */
	while ( (opt = getopt(argc, argv, "DLh:i:p:u:P:")) != EOF )
		switch ( opt ) {
			case 'D':
				mode = dump_mode;
				break;
			case 'L':
				mode = list_mode;
				break;

			case 'h':
				host = optarg;
				break;
			case 'i':
				index = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'u':
				user = optarg;
				break;

			case 'P':
				pwd = optarg;
				break;
		}

	if ( mode == no_mode ) {
		fputs("No mode specified.\n", stderr);
		goto done;
	}

	if ( host == NULL )
		host = getenv("QUIXOTE_IDX_HOST");
	if ( host == NULL ) {
		fputs("No host specified.\n", stderr);
		goto done;
	}

	if ( user == NULL )
		user = getenv("QUIXOTE_IDX_USER");
	if ( user == NULL ) {
		fputs("No user specified.\n", stderr);
		goto done;
	}

	if ( index == NULL ) {
		fputs("No endpoint index specified.\n", stderr);
		return 1;
	}

	if ( pwd == NULL )
		pwd = getenv("QUIXOTE_IDX_PWD");

	port = getenv("QUIXOTE_IDX_PORT");


	/* Initialize the index manipulation objects. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(NAAAIM, ESclient, client, ERR(goto done));
	if ( !client->init(client, host, port, index, user, pwd, bufr) )
		ERR(goto done);

	switch ( mode ) {
		case list_mode:
			if ( !client->list(client) )
				ERR(goto done);
			if ( !bufr->add(bufr, (void *) "\0", 1) )
				ERR(goto done);
			fprintf(stdout, "%s", bufr->get(bufr));
			break;

		case dump_mode:
			if ( !dump_index(client, bufr) ) {
				fputs("Index dump failed.\n", stderr);
				goto done;
			}
			break;

		default:
			break;
	}
	rc = 0;


 done:
	WHACK(bufr);
	WHACK(client);

	return rc;
}
