/** \file
 * This file implements a test driver for the Cell object which is
 * used to model the characteristics of a  cell in the Turing Security
 * Event Model.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


#define PGM "test-cell"


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

#include "tsem_event.h"
#include "Cell.h"


/**
 * Private function.
 *
 * This function is responsible for testing the parsing and processing
 * of a socket creation description.
 *
 * \return	A return value of zero indicates that the test utility
 *		ran correctly.  A value of one is returned to indicate
 *		an error.
 */

static int test_socket_create()

{
	int retn = 1;

	Buffer bufr = NULL;

	String entry = NULL;

	Cell cell = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, "event{process=runc, filename=none, type=socket_create, task_id=0000000000000000000000000000000000000000000000000000000000000000} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x3fffffffff} socket_create{family=1, type=1, protocol=00, kern=0}") )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);

	INIT(NAAAIM, Cell, cell, ERR(goto done));
	if ( !cell->parse(cell, entry, TSEM_SOCKET_CREATE) )
		ERR(goto done);
	if ( !cell->measure(cell) )
		ERR(goto done);
	if ( !cell->get_measurement(cell, bufr) )
		ERR(goto done);

	fputs("Arguments:\n", stdout);
	cell->dump(cell);

	entry->reset(entry);
	if ( !cell->format(cell, entry) )
		ERR(goto done);
	fputs("\nCell characteristics:\n", stdout);
	entry->print(entry);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(cell);

	return retn;
}


/**
 * Private function.
 *
 * This function is responsible for testing the parsing and processing
 * of a socket connection description.
 *
 * \return	A return value of zero indicates that the test utility
 *		ran correctly.  A value of one is returned to indicate
 *		an error.
 */

static int test_socket_connect()

{
	int retn = 1;

	Buffer bufr = NULL;

	String entry = NULL;

	Cell cell = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, "event{process=runc, filename=none, type=socket_create, task_id=0000000000000000000000000000000000000000000000000000000000000000} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x3fffffffff} socket_connect{family=2, data=1f407f0000010000000000000000}") )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);

	INIT(NAAAIM, Cell, cell, ERR(goto done));
	if ( !cell->parse(cell, entry, TSEM_SOCKET_CONNECT) )
		ERR(goto done);
	if ( !cell->measure(cell) )
		ERR(goto done);
	if ( !cell->get_measurement(cell, bufr) )
		ERR(goto done);

	fputs("Arguments:\n", stdout);
	cell->dump(cell);

	entry->reset(entry);
	if ( !cell->format(cell, entry) )
		ERR(goto done);
	fputs("\nCell characteristics:\n", stdout);
	entry->print(entry);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(cell);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	char *test = "unknown";

	String entry = NULL;

	Buffer bufr = NULL;

	Cell cell = NULL;


	while ( (opt = getopt(argc, argv, "t:")) != EOF )
		switch ( opt ) {
			case 't':
				test = optarg;
				break;
		}


	if ( strcmp(test, "unknown") == 0 ) {
		fprintf(stderr, "%s: Usage:\n", PGM);
		fputs("\t-t event_type\n", stderr);
		fputs("\n\t Event_types:\n", stderr);
		fputs("\t\tfile_open mmap_file socket_create " \
		      "socket_connect\n", stderr);
		goto done;
	}

	if ( strcmp(test, "socket_create") == 0 ) {
		test_socket_create();
		retn = 0;
		goto done;
	}

	if ( strcmp(test, "socket_connect") == 0 ) {
		test_socket_connect();
		retn = 0;
		goto done;
	}

	if ( (strcmp(test, "file_open") != 0) && \
	     (strcmp(test, "mmap_file") != 0) ) {
		fprintf(stderr, "%s: Unknown cell test: %s\n", PGM, test);
		goto done;
	}


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, "event{process=swapper/0, filename=/bin/bash-3.2.48, type=file_open, task_id=0000000000000000000000000000000000000000000000000000000000000000} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=3fffffffff} file{uid=0, gid=0, mode=o100755, name_length=16, name=e1cb9766d47adb4d514d5590dd247504a3aab7e67839d65a6c6f4c32fc120e5d, s_id=xvda, s_uuid=feadbeaffeadbeaffeadbeaffeadbeaf, digest=d2a6bfe0d8a2346d45518dcaaf47642808d6c605506bd0b8e42a65a76735b98e}") )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);


	INIT(NAAAIM, Cell, cell, ERR(goto done));
	if ( !cell->parse(cell, entry, TSEM_FILE_OPEN) )
		ERR(goto done);
	if ( !cell->measure(cell) )
		ERR(goto done);
	if ( !cell->get_measurement(cell, bufr) )
		ERR(goto done);
	cell->dump(cell);


	cell->reset(cell);
	if ( !cell->parse(cell, entry, TSEM_FILE_OPEN) )
		ERR(goto done);
	if ( !cell->measure(cell) )
		ERR(goto done);
	fputs("\nMeasurement after reset:\n", stdout);
	bufr->print(bufr);

	bufr->reset(bufr);
	cell->get_pseudonym(cell, bufr);
	fputs("\nPseudonym:\n", stdout);
	bufr->print(bufr);

	fputs("\nCell characteristics:\n", stdout);
	entry->reset(entry);
	if ( !cell->format(cell, entry) )
		ERR(goto done);
	entry->print(entry);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(entry);
	WHACK(cell);

	return retn;
}
