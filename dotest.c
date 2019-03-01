/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>

#include "NAAAIM.h"
#include "Buffer.h"
#include "SHA256.h"



extern int main(int argc, char *argv[])

{
	auto Buffer hashin;

	auto Sha256 sha256;


	if ( (hashin = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Failed buffer init.\n", stderr);
		return 0;
	}
		

	if ( (sha256 = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("Failed SHA256 init.\n", stderr);
		hashin->whack(hashin);
		return 0;
	}

	hashin->add(hashin, "hoot", 4);
	sha256->add(sha256, hashin);
	sha256->compute(sha256);
	sha256->print(sha256);


	sha256->whack(sha256);
	hashin->whack(hashin);
	return 0;
}
