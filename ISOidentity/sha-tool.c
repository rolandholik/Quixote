/** \file
 * This file implements a general purpose tool for computing digests
 * of values which are important in system trajectory measurements.
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
#include <SHA256.h>


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool null = false;

	int opt,
	    retn = 1;

	char *infile = NULL,
	     *string = NULL,
	     *base   = NULL,
	     *extend = NULL;

	Buffer bufr = NULL;

	Sha256 sha256 = NULL;

	File file = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "nb:e:f:s:")) != EOF )
		switch ( opt ) {
			case 'n':
				null = true;
				break;

			case 'b':
				base = optarg;
				break;

			case 'e':
				extend = optarg;
				break;

			case 'f':
				infile = optarg;
				break;

			case 's':
				string = optarg;
				break;
		}


	/* Generate a null hash. */
	if ( null ) {
		uint8_t lp;

		INIT(HurdLib, Buffer, bufr, ERR(goto done));

		for (lp= 0; lp < 32; ++lp)
			if ( !bufr->add(bufr, (unsigned char *) "\0", 1) )
				ERR(goto done);
		bufr->print(bufr);
	}


	/* Compute value of string. */
	if ( string != NULL ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		bufr->add(bufr, (unsigned char *) string, strlen(string));

		INIT(NAAAIM, Sha256, sha256, ERR(goto done));
		sha256->add(sha256, bufr);
		if ( !sha256->compute(sha256) )
			ERR(goto done);
		sha256->print(sha256);
	}

	/* Compute value of file. */
	if ( infile != NULL ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));

		INIT(HurdLib, File, file, ERR(goto done));
		file->open_ro(file, infile);
		if ( !file->slurp(file, bufr) )
			ERR(goto done);

		INIT(NAAAIM, Sha256, sha256, ERR(goto done));
		sha256->add(sha256, bufr);
		if ( !sha256->compute(sha256) )
			ERR(goto done);
		sha256->print(sha256);
	}

	/* Compute the value of a base and extension. */
	if ( (base != NULL) && (extend != NULL) ) {
		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		INIT(NAAAIM, Sha256, sha256, ERR(goto done));

		bufr->add_hexstring(bufr, base);
		sha256->add(sha256, bufr);

		bufr->reset(bufr);
		bufr->add_hexstring(bufr, extend);
		sha256->add(sha256, bufr);

		if ( !sha256->compute(sha256) )
			ERR(goto done);
		sha256->print(sha256);
	}


 done:
	WHACK(bufr);
	WHACK(file);
	WHACK(sha256);

	return retn;
}
