/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <HurdLib.h>

#include "NAAAIM.h"
#include "Buffer.h"
#include "RandomBuffer.h"
#include "SHA256.h"



extern int main(int argc, char *argv[])

{
	auto _Bool full = false;

	auto int retn;

	auto unsigned int bits = 256;

	auto RandomBuffer random = NULL;

	auto Sha256 sha256 = NULL;


	/* Get the organizational identifier and SSN. */
	while ( (retn = getopt(argc, argv, "Fb:")) != EOF )
		switch ( retn ) {
			case 'F':
				full = true;
				break;
			case 'b':
				bits = atoi(optarg);
				break;
		}



	if ( (random = NAAAIM_RandomBuffer_Init()) == NULL ) {
		fputs("Failed random buffer initialization.\n", stderr);
		return 1;
	}
	random->generate(random, bits / 8);

	if ( !full ) {
		random->print(random);
		goto done;
	}

	fputs("key:  ", stdout);
	random->print(random);

	if ( (sha256 = NAAAIM_Sha256_Init()) == NULL ) {
		fputs("Failed SHA256 initialization.\n", stderr);
		random->whack(random);
		return 1;
	}

	sha256->add(sha256, random->get_Buffer(random));
	sha256->compute(sha256);
	fputs("hash: ", stdout);
	sha256->print(sha256);


 done:
	if ( random != NULL )
		random->whack(random);
	if ( sha256 != NULL )
		sha256->whack(sha256);

	return 0;
}
