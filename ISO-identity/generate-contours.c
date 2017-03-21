/** \file
 * This file implements tracing of an execution trajectory path to
 * generate a behavioral contour map of the final state of the
 * modeled system.
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

#include "Actor.h"
#include "Subject.h"



/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool verbose = false;

	char *input_file = NULL;

	int opt,
	    retn = 1;

	uint32_t length;

	Buffer bufr = NULL;

	SHA256 sha256 = NULL;

	Actor actor = NULL;

	Subject subject = NULL;

	File trajectory = NULL;

	String entry = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "vi:")) != EOF )
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
	INIT(NAAAIM, SHA256, sha256, ERR(goto done));

	INIT(NAAAIM, Actor, actor, ERR(goto done));
	INIT(NAAAIM, Subject, subject, ERR(goto done));

	INIT(HurdLib, String, entry, ERR(goto done));

	INIT(HurdLib, File, trajectory, ERR(goto done));
	if ( !trajectory->open_ro(trajectory, input_file) )
		ERR(goto done);

	length = NAAAIM_IDSIZE;
	while ( trajectory->read_String(trajectory, entry) ) {
		actor->parse(actor, entry);
		if ( !actor->measure(actor) )
			ERR(goto done);
		if ( !bufr->add(bufr, (unsigned char * ) &length, \
				sizeof(length)) )
			ERR(goto done);
		if ( !actor->get_measurement(actor, bufr) )
			ERR(goto done);

		subject->parse(subject, entry);
		if ( !subject->measure(subject) )
			ERR(goto done);
		if ( !bufr->add(bufr, (unsigned char *) &length, \
				sizeof(length)) )
			ERR(goto done);
		if ( !subject->get_measurement(subject, bufr) )
			ERR(goto done);

		sha256->add(sha256, bufr);
		if ( !sha256->compute(sha256) )
			ERR(goto done);

		if ( verbose ) {
			entry->print(entry);
			fputc('\n', stdout);
			actor->dump(actor);
			fputc('\n', stdout);
			subject->dump(subject);
			fputc('\n', stdout);
			bufr->print(bufr);
			fputs("\nContour: ", stdout);
		}
		sha256->print(sha256);
		if ( verbose)
			fputc('\n', stdout);

		actor->reset(actor);
		subject->reset(subject);
		bufr->reset(bufr);
		sha256->reset(sha256);
		entry->reset(entry);
	}
	retn = 0;


 done:
	WHACK(bufr);
	WHACK(sha256);
	WHACK(actor);
	WHACK(subject);
	WHACK(entry);
	WHACK(trajectory);

	return retn;
}
