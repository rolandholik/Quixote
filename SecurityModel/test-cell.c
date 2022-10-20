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

#define SOCKET_CONNECT "event{process=bash, filename=none, type=socket_connect, task_id=77e90dbb8ae1da51e8dd0dc5f1500d9f6c26332252afa8fb8a4ca91a1ef60cac} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} socket_connect{family=1, addr=29c8abdfccdc1a3d51b989efea75d94b8453ad3014baa78d6a948cc92042c7ce}"

#define SOCKET_CONNECT_IPV4 "event{process=ncat, filename=none, type=socket_connect, task_id=ed7531f7052b0d02cfc0e26c74b0292cc2e46ca48e889f18670cabd75bd4e700} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} socket_connect{family=2, port=16415, addr=16777343}"

#define SOCKET_CONNECT_IPV6 "event{process=ncat, filename=none, type=socket_connect, task_id=ed7531f7052b0d02cfc0e26c74b0292cc2e46ca48e889f18670cabd75bd4e700} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x20000420} socket_connect{family=10, port=16415, flow=0, scope=0, addr=20014930017201100000000000000001}"

#define SOCKET_BIND "event{process=ncat, filename=none, type=socket_bind, task_id=6c3377303937c412988b0b5ec741fc01d94f1d3b8a68cb118406d2ca19502816} COE{uid=0, euid=0, suid=0, gid=0, egid=0, sgid=0, fsuid=0, fsgid=0, cap=0x7fffffffff} socket_bind{family=10, port=16415, flow=0, scope=0, addr=00000000000000000000000000000000}"



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

	fputs("\nArguments:\n", stdout);
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
 * \param arg	A pointer to a null-terminated buffer containing
 *		the socket connection definition to be tested.
 *
 * \param type	The event type being parsed.
 *
 * \return	A return value of zero indicates that the test utility
 *		ran correctly.  A value of one is returned to indicate
 *		an error.
 */

static int test_socket(char *arg, enum tsem_event_type type)

{
	int retn = 1;

	Buffer bufr = NULL;

	String entry = NULL;

	Cell cell = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));
	if ( !entry->add(entry, arg) )
		ERR(goto done);

	entry->print(entry);
	fputc('\n', stdout);

	INIT(NAAAIM, Cell, cell, ERR(goto done));
	if ( !cell->parse(cell, entry, type) )
		ERR(goto done);
	if ( !cell->measure(cell) )
		ERR(goto done);
	if ( !cell->get_measurement(cell, bufr) )
		ERR(goto done);
	fputs("Cell measurement:\n", stdout);
	bufr->print(bufr);

	fputs("\nArguments:\n", stdout);
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

	enum tsem_event_type type;

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
		fputs("\t\tfile_open mmap_file socket_create\n", stdout);
		fputs("\t\tsocket_connect socket_connect_ipv4 " \
		      "socket_connect_ipv6\n", stdout);
		fputs("\t\tsocket_bind\n", stdout);
		goto done;
	}

	if ( strcmp(test, "socket_create") == 0 ) {
		test_socket_create();
		retn = 0;
		goto done;
	}

	type = TSEM_SOCKET_CONNECT;
	if ( strcmp(test, "socket_connect") == 0 ) {
		retn = test_socket(SOCKET_CONNECT, type);
		goto done;
	}

	if ( strcmp(test, "socket_connect_ipv4") == 0 ) {
		retn = test_socket(SOCKET_CONNECT_IPV4, type);
		goto done;
	}

	if ( strcmp(test, "socket_connect_ipv6") == 0 ) {
		retn = test_socket(SOCKET_CONNECT_IPV6, type);
		goto done;
	}

	type = TSEM_SOCKET_BIND;
	if ( strcmp(test, "socket_bind") == 0 ) {
		retn = test_socket(SOCKET_BIND, type);
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
