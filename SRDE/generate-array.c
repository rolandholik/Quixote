/** \file
 * This file contains the implementation of a utility which reads
 * a binary file and generates to standard output an encoding of
 * the file in the form of an unsigned character array.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions local to this file. */
#define PGM "generate-array"
#define COPYRIGHT "2018"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include "NAAAIM.h"


/**
 * Internal public function.
 *
 * This method implements outputting of an error message and status
 * information on how to run the utility.
 *
 * \param err	A pointer to a null-terminated buffer holding the
 *		error message to be output.
 *
 * \return	No return value is defined.
 */

static void usage(char *err)

{
	fprintf(stdout, "%s: Binary array generation utility.\n", PGM);
	fprintf(stdout, "%s: (C)%s IDfusion, LLC\n", PGM, COPYRIGHT);

	if ( err != NULL )
		fprintf(stdout, "\n%s", err);

	fputc('\n', stdout);
	fputs("\nArguments:\n", stdout);
	fputs("\t-i:\tName of file containing the array contents.\n", stdout);
	fputs("\t-n:\tThe name of the array to be generated.\n", stdout);

	return;
}


/*
 * Main program.
 */

extern int main(int argc, char *argv[])

{
	_Bool retn = false;

	char *infile	 = NULL,
	     *array_name = NULL;

	uint8_t *sp;

	int opt;

	size_t lp;

	Buffer bufr = NULL;

	File file = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "i:n:")) != EOF )
		switch ( opt ) {
			case 'i':
				infile = optarg;
				break;
			case 'n':
				array_name = optarg;
				break;
		}


	if ( infile == NULL ) {
		usage("No input file name specified.");
		goto done;
	}

	if ( array_name == NULL ) {
		usage("No array name specified.");
		goto done;
	}


	/* Slurp in the input file. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, file, ERR(goto done));

	file->open_ro(file, infile);
	if ( !file->slurp(file, bufr) ) {
		fprintf(stderr, "%s: Error reading input file.\n", PGM);
		goto done;
	}


	/* Generate the named array of the given size. */
	fprintf(stdout, "static uint8_t %s[%lu] = {\n\t", array_name, \
		bufr->size(bufr));

	sp = (uint8_t *) bufr->get(bufr);
	for (lp= 1; lp <= bufr->size(bufr); ++lp) {
		fprintf(stdout, "0x%02x", sp[lp-1]);
		if ( (lp % 8) == 0 ) {
			if ( lp == bufr->size(bufr) )
				fputs("  \\\n", stdout);
			else
				fputs(", \\\n\t", stdout);
		}
		else
			fputs(", ", stdout);
	}
	fputs("};\n", stdout);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(file);

	return retn ? 0 : 1;
}
