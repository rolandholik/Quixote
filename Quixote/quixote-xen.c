/** \file
 * This file implements a prototype utility for interrogaing a Xen
 * stubdomain based Sancho implementation.
 */

/**************************************************************************
 * Copyright (c) 2020, Enjellic Systems Development, LLC. All rights reserved.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <xenstore.h>
#include <xengnttab.h>
#include <xenevtchn.h>

#include <HurdLib.h>
#include <Buffer.h>

#include <NAAAIM.h>
#include <XENduct.h>


/*
 * Program entry point.
 */

extern int main(int argc, char *argv[])

{
	char *domid = NULL;

	int opt,
	    retn = 1;

	uint32_t msg = 1;

	Buffer bufr = NULL;

	XENduct duct = NULL;


	/* Parse arguments. */
	while ( (opt = getopt(argc, argv, "s:")) != EOF )
		switch ( opt ) {
			case 's':
				domid = optarg;
				break;
		}


	/* Convert domain id to numeric value. */
	if ( domid == NULL ) {
		fputs("No Sancho domain specified.\n", stderr);
		goto done;
	}


	/* Wait for connection response. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, XENduct, duct, ERR(goto done));

	fputs("initializing device.\n", stderr);
	if ( !duct->init_device(duct, domid) )
		ERR(goto done);


	if ( !bufr->add(bufr, (void *) &msg, sizeof(msg)) )
		ERR(goto done);
	fputs("\nSending buffer.\n", stderr);
	bufr->hprint(bufr);
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);

	fputs("Receiving buffer.\n", stderr);
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		ERR(goto done);
	bufr->hprint(bufr);


	++msg;
	bufr->reset(bufr);

	if ( !bufr->add(bufr, (void *) &msg, sizeof(msg)) )
		ERR(goto done);
	fputs("\nSending buffer.\n", stderr);
	bufr->hprint(bufr);
	if ( !duct->send_Buffer(duct, bufr) )
		ERR(goto done);

	fputs("Receiving buffer.\n", stderr);
	bufr->reset(bufr);
	if ( !duct->receive_Buffer(duct, bufr) )
		ERR(goto done);
	bufr->hprint(bufr);

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(duct);

	return retn;
}
