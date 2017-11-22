#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sgx_tcrypto.h>

#include "test-fusion-interface.h"

#include "HurdLib.h"
#include "Buffer.h"
#include "String.h"


static void test_one(void)

{
	uint8_t lp;

	size_t len;

	static const unsigned char *input = \
		(const unsigned char *) "\xfe\xad\xbe\xaf";

	Buffer bufr = NULL;

	INIT(HurdLib, Buffer, bufr, ERR(goto done));


	fputs("Test number: 1\n", stdout);
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


 done:
	WHACK(bufr);

	return;
}


static void test_two(void)

{
	String string = NULL;

	static const char *string1 = "Testing string for String,",
			  *string2 = " appended string";


	fputs("Test number: 2\n", stdout);

	INIT(HurdLib, String, string, ERR(goto done));

	if ( !string->add(string, string1) )
		ERR(goto done);
	string->print(string);

	if ( !string->add(string, string2) )
		ERR(goto done);
	string->print(string);

	fputs("\nReset test:\n", stdout);
	string->reset(string);
	string->add(string, string1);
	if ( !string->add(string, string2) )
		ERR(goto done);
	string->print(string);


 done:
	WHACK(string);
	return;
}


void test_fusion(int test)

{
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
