/** \file
 * This file implements a utility for generating pseudonym definitions
 * from either a string or a security exchange event definition.
 *
 * The following command-line options specify the mode the utility is
 * to run in:
 *
 * -P: Default mode, input is expected to be a pathname.
 *
 * -T: Input is expected to be a security exchange event definition.
 *
 * Inputs are specified with the following command-line arguments.
 *
 * -i: The argument to this option will be the pathname or security
 *     event definition for which the pseudonym is to be calculated.
 *
 * -f: The argument to this option is a file whose contents are either
 *     pathnames or security exchange event definitions.

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

#include "tsem_event.h"
#include "Cell.h"


/**
 * Private function.
 *
 * This function implements the computation of a pseudonym from a string
 * containing the pathname of the pseudonym.
 *
 * \param path		The object containing the path from which the
 *			pseudonym is to be generated
 *
 * \return		A boolean value is used to indicate whether
 *			or not generation of the pseudonym succeeded.
 *			A false value indicates a failure while a true
 *			value indicates the pseudonym was successfully
 *			generated.
 */

static _Bool do_path(CO(String, path))

{
	_Bool retn = false;

	uint32_t length = path->size(path);

	Buffer bufr = NULL;

	Sha256 pseudonym = NULL;


	/* Add the length of the path and the path itself. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) &length, sizeof(length)) )
		ERR(goto done);
	if ( !bufr->add(bufr, (void *) path->get(path), length) )
		ERR(goto done);

	INIT(NAAAIM, Sha256, pseudonym, ERR(goto done));
	if ( !pseudonym->add(pseudonym, bufr) )
		ERR(goto done);
	if ( !pseudonym->compute(pseudonym) )
		ERR(goto done);

	fputs("pseudonym ", stdout);
	pseudonym->print(pseudonym);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(pseudonym);

	return retn;
}


/**
 * Private function.
 *
 * This function implements the computation of a pseudonum from a single
 * trajectory entry.
 *
 * \param event		The object containing security exchange event.
 *
 * \return		A boolean value is used to indicate whether
 *			or not generation of the pseudonym succeeded.
 *			A false value indicates a failure while a true
 *			value indicates the pseudonym was successfully
 *			generated.
 */

static _Bool do_trajectory(CO(String, event))

{
	_Bool retn = false;

	Buffer bufr = NULL;

	Cell cell = NULL;


	INIT(NAAAIM, Cell, cell, ERR(goto done));
	if ( !cell->parse(cell, event, TSEM_FILE_OPEN) )
		ERR(goto done);

	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !cell->get_pseudonym(cell, bufr) )
		ERR(goto done);

	fputs("pseudonym ", stdout);
	bufr->print(bufr);
	retn = true;


 done:
	WHACK(cell);
	WHACK(bufr);

	return retn;
}


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *input_file   = NULL,
	     *input_string = NULL;

	int opt,
	    retn = 1;

	enum {
		path_mode,
		trajectory_mode,
	} mode = path_mode;

	String str = NULL;

	File file = NULL;


	/* Parse and verify arguments. */
	while ( (opt = getopt(argc, argv, "PTf:i:")) != EOF )
		switch ( opt ) {
			case 'P':
				mode = path_mode;
				break;
			case 'T':
				mode = trajectory_mode;
				break;

			case 'f':
				input_file = optarg;
				break;
			case 'i':
				input_string = optarg;
				break;

		}

	if ( (input_file == NULL) && (input_string == NULL) ) {
		fputs("No input source specified.\n", stderr);
		goto done;
	}

	INIT(HurdLib, String, str, ERR(goto done));

	if ( input_string != NULL ) {
		if ( !str->add(str, input_string) )
			ERR(goto done);
	}

	if ( input_file != NULL ) {
		INIT(HurdLib, File, file, ERR(goto done));
		if ( !file->open_ro(file, input_file) )
			ERR(goto done);
	}


	/* Handle trajectory definition in a string. */
	if ( (mode == trajectory_mode) && (input_string != NULL) ) {
		if ( !do_trajectory(str) )
			ERR(goto done);
	}


	/* Handle a file of trajectory definitions. */
	if ( (mode == trajectory_mode) && (input_file != NULL) ) {
		while ( file->read_String(file, str) ) {
			if ( !do_trajectory(str) )
				ERR(goto done);
			str->reset(str);
		}
	}


	/* Handle a pathname. */
	if ( (mode == path_mode) && (input_string != NULL) ) {
		if ( !do_path(str) )
			ERR(goto done);
	}


	/* Handle a file of pathnames.. */
	if ( (mode == path_mode) && (input_file != NULL) ) {
		while ( file->read_String(file, str) ) {
			if ( !do_path(str) )
				ERR(goto done);
			str->reset(str);
		}
	}


	retn = 0;


 done:
	WHACK(str)
	WHACK(file);

	return retn;
}
