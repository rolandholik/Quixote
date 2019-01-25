#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "NAAAIM.h"
#include "Buffer.h"
#include "SHA256.h"



extern int main(int argc, char *argv[])

{
	auto char *p,
		  input[256];

	auto Buffer bufr;

	auto Sha256 sha256;

	if ( (sha256 = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("Failed SHA256 init.\n", stderr);
		return 0;
	}

	if ( (bufr = HurdLib_Buffer_Init()) == NULL ) {
		fputs("Failed buffer init.\n", stderr);
		sha256->whack(sha256);
		return 0;
	}


	while ( fgets(input, sizeof(input), stdin) ) {
		if ( (p = strchr(input, '\n')) != NULL )
			*p = '\0';
		bufr->add_hexstring(bufr, input);
		sha256->add(sha256, bufr);
		bufr->reset(bufr);
	}

	sha256->compute(sha256);
	fputc('\n', stdout);
	sha256->print(sha256);


	bufr->whack(bufr);
	sha256->whack(sha256);

	return 0;
}
