/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <string.h>

#include "NAAAIM.h"
#include "Buffer.h"
#include "SHA256_hmac.h"
#include "RandomBuffer.h"


extern int main(int argc, char **argv)

{
	auto char *p,
		  inbufr[80];

	auto int retn = 1;

	auto unsigned int lp = 0;

	auto Buffer key   = NULL,
		    input = NULL;

	auto RandomBuffer random = NULL;

	auto SHA256_hmac hmac = NULL;


	key = HurdLib_Buffer_Init();
	input = HurdLib_Buffer_Init();
	if ( (key == NULL) || (input == NULL) ) {
		fputs("Failed buffer initializations.\n", stderr);
		goto done;
	}

	if ( (random = NAAAIM_RandomBuffer_Init()) == NULL ) {
		fputs("Failed random initialization.\n", stderr);
		goto done;
	}

	/* Set initial key. */
	random->generate(random, 256 / 8);
	key->add_Buffer(key, random->get_Buffer(random));

	/* Set initial input. */
	random->generate(random, 256 / 8);

	/*
	 * Loop over the input and iteratively feed back the hash output
	 * as input keyed with the random key.
	 */
	if ( (hmac = NAAAIM_SHA256_hmac_Init(key)) == NULL ) {
		fputs("Failed hash creation.\n", stderr);
		goto done;
	}
	hmac->add_Buffer(hmac, random->get_Buffer(random));

	while ( fgets(inbufr, sizeof(inbufr), stdin) ) {
		if ( (p = strchr(inbufr, '\n')) != NULL )
			*p = '\0';

		hmac->compute(hmac);
		fprintf(stdout, "%s ", inbufr);
		hmac->print(hmac);

		input->reset(input);
		input->add_Buffer(input, hmac->get_Buffer(hmac));
		hmac->reset(hmac);
		hmac->add_Buffer(hmac, input);

		if ( (++lp % 1000) == 0 )
			random->generate(random, 256 / 8);
	}
	retn = 0;

		
 done:
	if ( key != NULL )
		key->whack(key);
	if ( input != NULL )
		input->whack(input);
	if ( random != NULL )
		random->whack(random);
	if ( hmac != NULL )
		hmac->whack(hmac);

	return retn;
}
