#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sgx_tcrypto.h>

#include "test-fusion-interface.h"

#include <HurdLib.h>
#include <Buffer.h>

#include "SHA256.h"
#include "RandomBuffer.h"
#include "Curve25519.h"


void test_one()

{
	uint8_t lp;

	size_t len;

	static const unsigned char *input = \
		(const unsigned char *) "abc";

	Buffer bufr = NULL;

	SHA256 sha256 = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(NAAAIM, SHA256, sha256, ERR(goto done));

	len = strlen((char *) input);
	fputs("Input:\n", stdout);
	for (lp= 0; lp < len; ++lp)
		fprintf(stdout, "%02x", input[lp]);
	fputs("\n\n", stdout);

	if ( !bufr->add(bufr, input, len) )
		ERR(goto done);
	fputs("Buffer:\n", stdout);
	bufr->print(bufr);
	fputc('\n', stdout);
	bufr->hprint(bufr);

	fputc('\n', stdout);
	fputs("SHA256:\n", stdout);
	sha256->add(sha256, bufr);
	if ( !sha256->compute(sha256) )
		ERR(goto done);
	sha256->print(sha256);


 done:
	WHACK(bufr);
	WHACK(sha256)

	return;
}


void test_two()

{
	Buffer b;

	RandomBuffer random = NULL;


	INIT(NAAAIM, RandomBuffer, random, ERR(goto done));
	b = random->get_Buffer(random);

	fputs("8 bytes:\n", stdout);
	if ( !random->generate(random, sizeof(uint64_t)) )
		ERR(goto done);
	b->print(b);

	fputs("18 bytes:\n", stdout);
	if ( !random->generate(random, 18) )
		ERR(goto done);
	b->print(b);

	fputs("32 bytes:\n", stdout);
	if ( !random->generate(random, 32) )
		ERR(goto done);
	b->print(b);


 done:
	WHACK(random);

	return;
}


void test_three(void)

{
	Curve25519 ours	  = NULL,
		   theirs = NULL;

	Buffer b,
	       shared = NULL;


	/* Create the public/private keypairs. */
	INIT(NAAAIM, Curve25519, ours, goto done);
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


	/* Generate and confirm the shared secrets. */
	INIT(HurdLib, Buffer, shared, goto done);
	if ( !ours->compute(ours, theirs->get_public(theirs), shared) )
		goto done;
	fputs("\nOur key:\n", stdout);
	shared->print(shared);

	shared->reset(shared);
	if ( !theirs->compute(theirs, ours->get_public(ours), shared) )
		goto done;
	fputs("\nTheir key:\n", stdout);
	shared->print(shared);


 done:
	WHACK(ours);
	WHACK(theirs);
	WHACK(shared);

	return;
}


void test_naaaim(unsigned int test)

{

	fprintf(stdout, "Test number: %u\n", test);
	switch ( test ) {
		case 1:
			test_one();
			break;
		case 2:
			test_two();
			break;
		case 3:
			test_three();
			break;

		default:
			fputs("Invalid test.\n", stderr);
			break;
	}
	fprintf(stdout, "End test: %d\n", test);


	return;
}
