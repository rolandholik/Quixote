#include <stdio.h>
#include <stdbool.h>

#include <openssl/rand.h>

#include "NAAAIM.h"
#include "Buffer.h"
#include "RandomBuffer.h"
#include "SHA256.h"



extern int main(int argc, char *argv[])

{
	auto RandomBuffer random;

	auto SHA256 sha256;


	if ( (random = NAAAIM_RandomBuffer_Init()) == NULL ) {
		fputs("Failed random buffer initialization.\n", stderr);
		return 1;
	}

	random->generate(random, 8);
	random->print(random);

	if ( (sha256 = NAAAIM_SHA256_Init()) == NULL ) {
		fputs("Failed SHA256 initialization.\n", stderr);
		random->whack(random);
		return 1;
	}

	sha256->add(sha256, random->get_Buffer(random));
	sha256->compute(sha256);
	sha256->print(sha256);

	random->whack(random);
	sha256->whack(sha256);
	return 0;
}
