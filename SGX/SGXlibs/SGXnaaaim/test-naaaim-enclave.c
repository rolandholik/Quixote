#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sgx_tcrypto.h>

#include "test-fusion-interface.h"

#include <HurdLib.h>
#include <Buffer.h>

#include "SHA256.h"
#include "RandomBuffer.h"


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
		default:
			fputs("Invalid test.\n", stderr);
			break;
	}
	fprintf(stdout, "End test: %d\n", test);


	return;
}
