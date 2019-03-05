/** \file
 * This file implements the computation of the boot aggregate value
 * which is the initial measurement extended into the TPM.  The
 * values used to compute the aggregate value are derived from the
 * actor and subject values from the first line in the following
 * pseudo-file:
 *
 *	/sys/kernel/security/ima/ascii_runtime_measurements
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

#include <NAAAIM.h>
#include <SHA256.h>


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	char *actor   = NULL,
	     *subject = NULL;

	int opt,
	    retn = 1;

	uint32_t length = NAAAIM_IDSIZE;

	Buffer bufr = NULL;

	Sha256 sha256 = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "a:s:")) != EOF )
		switch ( opt ) {
			case 'a':
				actor = optarg;
				break;
			case 's':
				subject = optarg;
				break;
		}


	/* Validate actor and subject aggregate values. */
	if ( actor == NULL ) {
		fputs("No actor aggregate value.\n", stderr);
		goto done;
	}
	if ( strlen(actor) != NAAAIM_IDSIZE*2 ) {
		fputs("Invalid actor aggregate value specified.\n", stderr);
		goto done;
	}

	if ( subject == NULL ) {
		fputs("No subject aggregate value.\n", stderr);
		goto done;
	}
	if ( strlen(subject) != NAAAIM_IDSIZE*2 ) {
		fputs("Invalid subject aggregate value specified.\n", stderr);
		goto done;
	}


	/* Initialize objects. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));


	/* Add the length and actor value. */
	if ( !bufr->add(bufr, (unsigned char * ) &length, sizeof(length)) )
		ERR(goto done);
	if ( !bufr->add_hexstring(bufr, actor) )
		ERR(goto done);

	if ( !bufr->add(bufr, (unsigned char * ) &length, sizeof(length)) )
		ERR(goto done);
	if ( !bufr->add_hexstring(bufr, subject) )
		ERR(goto done);


	/* Compute the measurement over the measurement buffer. */
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	sha256->print(sha256);
	retn = 0;

 done:
	WHACK(bufr);
	WHACK(sha256);

	return retn;
}
