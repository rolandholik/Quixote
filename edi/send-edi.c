/** \file
 *
 * This file implements a command-line client for sending an EDI
 * transaction.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <Duct.h>

#include "edi.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	long int lp,
		 edi_cnt = 1,
		 edi_repeat = 1;

	long long int start,
		      end;

	char *host   = NULL,
	     *edi    = NULL,
	     *cnt    = NULL,
	     *repeat = NULL;

	struct timeval the_time;

	Buffer bufr  = NULL,
	       reply = NULL;

	File edi_file = NULL;

	Duct duct = NULL;


	/* Parse options and set mode. */
	while ( (opt = getopt(argc, argv, "c:h:i:r:")) != EOF )
		switch ( opt ) {
			case 'c':
				cnt = optarg;
				break;
			case 'h':
				host = optarg;
				break;

			case 'i':
				edi = optarg;
				break;
			case 'r':
				repeat = optarg;
				break;
		}

	/* Set identity type. */
	if ( host == NULL ) {
		fputs("No EDI hostname specified.\n", stderr);
		goto done;
	}
	if ( edi == NULL ) {
		fputs("No EDI file specified.\n", stderr);
		goto done;
	}

	/* Set the size of the EDI transaction. */
	if ( cnt != NULL ) {
		edi_cnt = strtol(cnt, NULL, 10);
		if ( errno == ERANGE )
			goto done;
		if ( edi_cnt < 0 )
			goto done;
	}

	if ( repeat != NULL ) {
		edi_repeat = strtol(repeat, NULL, 10);
		if ( errno == ERANGE )
			goto done;
		if ( edi_repeat < 0 )
			goto done;
	}

	if ( gettimeofday(&the_time, NULL) == -1 ) {
		fputs("Failed to get start time.\n", stderr);
		goto done;
	}
	start = (the_time.tv_sec * 1000000) + the_time.tv_usec;

	/* Open the EDI access port connection. */
	INIT(NAAAIM, Duct, duct, goto done);
	if ( !duct->init_client(duct) ) {
		fputs("Cannot initialize access connection.\n", stderr);
		goto done;
	}
	if ( !duct->init_port(duct, host, ACCESS_PORT) ) {
		fputs("Cannot initialize access connection.\n", stderr);
		goto done;
	}


	/* Open the EDI transaction file and send it. */
	INIT(HurdLib, Buffer, bufr, goto done);
	INIT(HurdLib, Buffer, reply, goto done);

	INIT(HurdLib, File, edi_file, goto done);
	if ( !edi_file->open_ro(edi_file, edi) ) {
		fputs("Error opening EDI file.\n", stderr);
		goto done;
	}

	for (lp= 0; lp < edi_cnt; ++lp) {
		if ( !edi_file->slurp(edi_file, bufr) ) {
			fputs("Unable to read EDI transaction.\n", stderr);
			goto done;
		}
		if ( edi_file->seek(edi_file, 0) != 0 ) {
			fputs("Error resetting file.\n", stderr);
			goto done;
		}
	}

	fprintf(stdout, "count=%ld, repeat=%ld\n", edi_cnt, edi_repeat);
	for (lp= 0; lp < edi_repeat; ++lp) {
		fprintf(stdout, "Sending buffer, cnt=%lu:\n", edi_cnt);
		bufr->print(bufr);

		if ( !duct->send_Buffer(duct, bufr) ) {
			fputs("Error sending buffer.\n", stderr);
			goto done;
		}

		if ( !duct->receive_Buffer(duct, reply) ) {
			fputs("Error receiving buffer.\n", stderr);
			goto done;
		}
		fputs("Received response:\n", stdout);
		reply->hprint(reply);
		reply->reset(reply);
	}

	/* Determine transaction time. */
	if ( gettimeofday(&the_time, NULL) == -1 ) {
		fputs("Failed to get end time.\n", stderr);
		goto done;
	}
	end = (the_time.tv_sec * 1000000) + the_time.tv_usec;
	fprintf(stdout, "Transaction time: microseconds=%llu\n", end - start);
	retn = 0;


 done:
	WHACK(bufr);
	WHACK(reply);
	WHACK(edi_file);
	WHACK(duct);

	return retn;
}
