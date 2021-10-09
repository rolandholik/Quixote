/** \file
 * This file implements the tracing of an execution trajectory path
 * with computation of the measurement of the platform.  The measurement
 * consists of the soft measurement which is the extension sum of
 * the host identity projected behavior trajectory points.  In addition
 * the hardware based measurement which is an extension of of the
 * aggregate boot measurement is computed.
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

#include "COE.h"
#include "Cell.h"



/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	_Bool verbose = false;

	char *contours	= NULL,
	     *hostid	= NULL,
	     *aggregate	= NULL;

	unsigned char measurement[NAAAIM_IDSIZE];

	int opt,
	    retn = 1;

	Buffer b,
	       bufr = NULL,
	       host = NULL;

	Sha256 sha256 = NULL;

	File trajectory = NULL;

	String entry = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "va:c:h:")) != EOF )
		switch ( opt ) {
			case 'v':
				verbose = true;
				break;
			case 'a':
				aggregate = optarg;
				break;
			case 'c':
				contours = optarg;
				break;
			case 'h':
				hostid = optarg;
				break;
		}

	if ( contours == NULL ) {
		fputs("No contours file specifed.\n", stderr);
		goto done;
	}

	if ( aggregate == NULL ) {
		fputs("No aggregate file specified.\n", stderr);
		goto done;
	}
	if ( strlen(aggregate) != NAAAIM_IDSIZE*2 ) {
		fputs("Invalid aggregate measurement specified.\n", stderr);
		goto done;
	}

	if ( hostid == NULL ) {
		fputs("No host identifier file specified.\n", stderr);
		goto done;
	}
	if ( strlen(hostid) != NAAAIM_IDSIZE*2 ) {
		fputs("Invalid host identity specified.\n", stderr);
		goto done;
	}
	INIT(HurdLib, Buffer, host, ERR(goto done));
	if ( !host->add_hexstring(host, hostid) )
		ERR(goto done);


	/* Initialize objects. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, Sha256, sha256, ERR(goto done));


	/* Initialize the measurement with boot aggregate. */
	memset(measurement, '\0', sizeof(measurement));

	if ( strlen(aggregate)/2 != NAAAIM_IDSIZE ) {
		fputs("Invalid aggregate value specified.\n", stderr);
		goto done;
	}
	if ( verbose )
		fprintf(stdout, "a: %s\n", aggregate);
		

	/* Host extend the aggregate contour point. */
	bufr->add_hexstring(bufr, hostid);
	bufr->add_hexstring(bufr, aggregate);

	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	if ( verbose ) {
		fputs("h: ", stdout);
		sha256->print(sha256);
	}
		

	/*
	 * Extend the starting measurement with the host aggregate
	 * value.
	 */
	b = sha256->get_Buffer(sha256);
	bufr->reset(bufr);
	bufr->add(bufr, (unsigned char *) measurement, \
		  sizeof(measurement));
	bufr->add_Buffer(bufr, b);

	sha256->reset(sha256);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);

	b = sha256->get_Buffer(sha256);
	memcpy(measurement, b->get(b), sizeof(measurement));
	if ( verbose ) {
		fputs("m: ", stdout);
		b->print(b);
		fputc('\n', stdout);
	}

	bufr->reset(bufr);
	sha256->reset(sha256);


	/* Read and process the contours file. */
	INIT(HurdLib, File, trajectory, ERR(goto done));
	if ( !trajectory->open_ro(trajectory, contours) )
		ERR(goto done);

	INIT(HurdLib, String, entry, ERR(goto done));

	while ( trajectory->read_String(trajectory, entry) ) {
		/* Host extend the contour point. */
		if ( !bufr->add_hexstring(bufr, entry->get(entry)) )
		     ERR(goto done);
		if ( verbose ) {
			fputs("c: ", stdout);
			bufr->print(bufr);
		}

		bufr->reset(bufr);
		bufr->add_Buffer(bufr, host);
		if ( !bufr->add_hexstring(bufr, entry->get(entry)) )
		     ERR(goto done);

		sha256->add(sha256, bufr);
		if ( !sha256->compute(sha256) )
			ERR(goto done);
		if ( verbose ) {
			fputs("h: ", stdout);
			sha256->print(sha256);
		}

		/* Extend the current measurement. */
		bufr->reset(bufr);
		bufr->add(bufr, (unsigned char *) measurement, \
			  sizeof(measurement));
		bufr->add_Buffer(bufr, sha256->get_Buffer(sha256));

		sha256->reset(sha256);
		sha256->add(sha256, bufr);
		if ( verbose ) {
			fputs("   ", stdout);
			bufr->print(bufr);
		}
		if ( !sha256->compute(sha256) )
			ERR(goto done);

		b = sha256->get_Buffer(sha256);
		memcpy(measurement, b->get(b), sizeof(measurement));
		if ( verbose ) {
			fputs("m: ", stdout);
			b->print(b);
		}

		bufr->reset(bufr);
		sha256->reset(sha256);
		entry->reset(entry);

		if ( verbose )
			fputc('\n', stdout);
	}

	if ( !verbose ) {
		bufr->reset(bufr);
		bufr->add(bufr, measurement, sizeof(measurement));
		bufr->print(bufr);
	}

	retn = 0;


 done:
	WHACK(host);
	WHACK(trajectory);
	WHACK(entry);
	WHACK(bufr);
	WHACK(sha256);

	return retn;
}
