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
#include <File.h>

#include <NAAAIM.h>
#include <RandomBuffer.h>

#include "Curve25519.h"


extern int main(int argc, char *argv[])

{
	_Bool retn = 1;

	uint8_t lp;

	uint8_t their_public[32],
		their_private[32];

	uint8_t our_public[32],
		our_private[32];

	uint8_t shared_key[32],
		use_key[32];

	uint8_t bp[32] = {9};

	Curve25519 ec = NULL;

	Buffer b;

	RandomBuffer rnd = NULL;


	INIT(NAAAIM, Curve25519, ec, goto done);

	/* Create our public/private keypair. */
	INIT(NAAAIM, RandomBuffer, rnd, goto done);
	if ( !rnd->generate(rnd, 32) )
		goto done;
	b = rnd->get_Buffer(rnd);
	memcpy(our_private, b->get(b), b->size(b));
	fputs("Our private:\n", stdout);
	b->print(b);

	ec->curve25519(ec, our_public, our_private, bp);
	fputs("Our public key: \n", stdout);
	for (lp= 0; lp < sizeof(our_public); ++lp)
		fprintf(stdout, "%02x", our_public[lp]);
	fputs("\n\n", stdout);

	/* Create their public/private keypair. */
	if ( !rnd->generate(rnd, 32) )
		goto done;
	b = rnd->get_Buffer(rnd);
	memcpy(their_private, b->get(b), b->size(b));
	fputs("Their private:\n", stdout);
	b->print(b);

	ec->curve25519(ec, their_public, their_private, bp);
	fputs("Their public key: \n", stdout);
	for (lp= 0; lp < sizeof(their_public); ++lp)
		fprintf(stdout, "%02x", their_public[lp]);
	fputs("\n\n", stdout);


	/* Generate a shared key. */
	ec->curve25519(ec, shared_key, our_private, their_public);
	fputs("Host key: \n", stdout);
	for (lp= 0; lp < sizeof(shared_key); ++lp)
		fprintf(stdout, "%02x", shared_key[lp]);
	fputs("\n\n", stdout);

	/* Extract shared key. */
	ec->curve25519(ec, use_key, their_private, our_public);
	fputs("Client key: \n", stdout);
	for (lp= 0; lp < sizeof(use_key); ++lp)
		fprintf(stdout, "%02x", use_key[lp]);
	fputs("\n", stdout);
	


	retn = 0;

 done:
	WHACK(ec);
	WHACK(rnd);

	return retn;
}
