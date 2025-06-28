/** \file
 * This file implements the a unit test for the JSONparser object that
 * tests the JSON document parser.
 */

/**************************************************************************
 * Copyright (c) 2025, Enjellic Systems Development, LLC. All rights reserved.
 *
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#include <stdio.h>
#include <stdlib.h>

#include <HurdLib.h>
#include "Buffer.h"
#include "String.h"

#include "NAAAIM.h"
#include "JSONparser.h"


#define INDEX_DOC "{\"took\":0,\"timed_out\":false,\"_shards\":{\"total\":1,\"successful\":1,\"skipped\":0,\"failed\":0},\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"},\"max_score\":1.0,\"hits\":[{\"_index\":\"quixote-test\",\"_id\":\"JDJ6a5cBR_QvOt5f-l0b\",\"_score\":1.0,\"_source\":{\"export\": {\"boot_id\": \"99e6b84c-58ae-4c97-a196-640434c48a54\", \"@timestamp\": \"2025-05-31T14:43:17.473493805\", \"type\": \"event\"}, \"event\": {\"pid\": \"10728\", \"tnum\": \"10728\", \"context\": \"35\", \"number\": \"326\", \"process\": \"runc:[2:INIT]\", \"type\": \"inode_getattr\", \"ttd\": \"5497\", \"p_ttd\": \"5497\", \"task_id\": \"9111fe4f18ddc43957d30997c02d0e7f4e8dd76c0bff7dcf54fef959c9a60d2a\", \"p_task_id\": \"9111fe4f18ddc43957d30997c02d0e7f4e8dd76c0bff7dcf54fef959c9a60d2a\", \"ts\": \"1078866308\"}, \"COE\": {\"uid\": \"0\", \"euid\": \"0\", \"suid\": \"0\", \"gid\": \"0\", \"egid\": \"0\", \"sgid\": \"0\", \"fsuid\": \"0\", \"fsgid\": \"0\", \"capeff\": \"0x1fdffffffff\"}, \"inode_getattr\": {\"path\": {\"inode\": {\"uid\": \"0\", \"gid\": \"0\", \"mode\": \"040555\", \"s_magic\": \"0x9fa0\", \"s_id\": \"proc\", \"s_uuid\": \"00000000000000000000000000000000\"}, \"path\": {\"type\": \"namespace\", \"pathname\": \"/\"}}}}}]}}"


/*
 * Main program starts here.
 */

int main(int argc, char *argv[])

{
	int hit_count;

	Buffer bufr = NULL;

	String str = NULL;

	JSONparser parser = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) INDEX_DOC, sizeof(INDEX_DOC) - 1) )
		ERR(goto done);

	INIT(NAAAIM, JSONparser, parser, ERR(goto done));
	if ( !parser->parse_Buffer(parser, bufr) )
		ERR(goto done);

	if ( !parser->select_object(parser, "hits") ) {
		fputs("Hits is not an object.\n", stdout);
		goto done;
	}

	if ( !parser->select_array(parser, "hits") ) {
		fputs("Hits is not an object.\n", stdout);
		goto done;
	}

	if ( !parser->select_object(parser, "total") ) {
		fputs("total object not found.\n", stdout);
		goto done;
	}
	if ( !parser->select_integer(parser, "value") ) {
		fputs("value integer not found.\n", stdout);
		goto done;
	}
	if ( !parser->get_integer(parser, &hit_count) ) {
		fputs("Failed to get value of selected integer.\n", stdout);
		goto done;
	}
	fprintf(stdout, "Hit count: %d\n", hit_count);

	if ( !parser->get_array_size(parser, &hit_count) ) {
		fputs("Failed to get array size.\n", stdout);
		goto done;
	}
	if ( !parser->select_array_object(parser, 0) ) {
		fputs("Failed to select array object.\n", stdout);
		goto done;
	}

	if ( !parser->select_object(parser, "_source") ) {
		fputs("Failed to select source object.\n", stdout);
		goto done;
	}
	parser->print(parser);

	INIT(HurdLib, String, str, ERR(goto done));
	if ( !parser->get_object_String(parser, str) )
		ERR(goto done);
	fprintf(stdout, "\n%s\n", str->get(str));


 done:
	WHACK(bufr);
	WHACK(str);
	WHACK(parser);

	return 0;
}
