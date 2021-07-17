/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include "Curve25519.h"


extern int main(int argc, char *argv[])

{
	_Bool retn = 1;

	Curve25519 ours	  = NULL,
		   theirs = NULL;

	Buffer b,
	       shared = NULL;


	/* Create the public/private keypairs. */
	INIT(NAAAIM, Curve25519, ours, goto done);
	fputs("Generate our keypair.\n", stdout);
	if ( !ours->generate(ours) )
		goto done;
	fputs("Our public:\n", stdout);
	b = ours->get_public(ours);
	b->print(b);

	INIT(NAAAIM, Curve25519, theirs, goto done);
	if ( !theirs->generate(theirs) )
		goto done;
	fputs("\nTheir public:\n", stdout);
	b = theirs->get_public(theirs);
	b->print(b);

	/* Generate a shared secret. */
	INIT(HurdLib, Buffer, shared, goto done);
	if ( !ours->compute(ours, theirs->get_public(theirs), shared) )
		goto done;
	fputs("\nOur key:\n", stdout);
	shared->print(shared);

	/* Confirm the shared secret. */
	shared->reset(shared);
	if ( !theirs->compute(theirs, ours->get_public(ours), shared) )
		goto done;
	fputs("\nTheir key:\n", stdout);
	shared->print(shared);

	retn = 0;


 done:
	WHACK(ours);
	WHACK(theirs);
	WHACK(shared);

	return retn;
}
