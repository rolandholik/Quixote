/** \file
 * This file implements a tool for setting the key and initialization for
 * a platform management token.
 */

/**************************************************************************
 * (C)Copyright 2015, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


/* Local defines. */
#define IV_SIZE 128
#define KEY_SIZE 256


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <RSAkey.h>
#include <SmartCard.h>
#include <IPC.h>
#include <RandomBuffer.h>

#include "MGMTsupvr.h"


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	char *iv_value	= NULL,
	     *key_value = NULL;

	Buffer iv  = NULL,
	       key = NULL;

	RandomBuffer rndbufr = NULL;

	MGMTsupvr supvr = NULL;


	while ( (opt = getopt(argc, argv, "i:k:")) != EOF )
		switch ( opt ) {
			case 'i':
				iv_value = optarg;
				break;
			case 'k':
				key_value = optarg;
				break;
		}

	if ( (iv_value == NULL) || (key_value == NULL) ) {
		fputs("Initialization vector and/or key not specifed.\n", \
		      stderr);
		return 1;
	}


	/* Generate and/or convert provided values. */
	INIT(HurdLib, Buffer, iv, goto done);
	INIT(HurdLib, Buffer, key, goto done);
	INIT(NAAAIM, RandomBuffer, rndbufr, goto done);
	
	if ( strcmp(iv_value, "gen") == 0 ) {
		if ( !rndbufr->generate(rndbufr, IV_SIZE/8) )
			ERR(goto done);
		if ( !iv->add_Buffer(iv, rndbufr->get_Buffer(rndbufr)) )
			ERR(goto done);
	}
	else {
		if ( !iv->add_hexstring(iv, iv_value) )
			ERR(goto done);
	}

	if ( strcmp(key_value, "gen") == 0 ) {
		if ( !rndbufr->generate(rndbufr, KEY_SIZE/8) )
			ERR(goto done);
		if ( !key->add_Buffer(key, rndbufr->get_Buffer(rndbufr)) )
			ERR(goto done);
	}
	else {
		if ( !key->add_hexstring(key, key_value) )
			ERR(goto done);
	}


	INIT(NAAAIM, MGMTsupvr, supvr, goto done);
	if ( !supvr->set_iv_key(supvr, iv, key) )
		ERR(goto done);
	if ( !supvr->write_key(supvr, "liu.key_pub", NULL, NULL) )
		ERR(goto done);

 done:
	WHACK(iv);
	WHACK(key);
	WHACK(rndbufr);
	WHACK(supvr);

	return retn;
}
