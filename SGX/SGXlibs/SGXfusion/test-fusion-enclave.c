#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sgx_tcrypto.h>

#include "test-fusion-interface.h"

#include "HurdLib.h"
#include "Buffer.h"


void test_fusion(int test)

{
	uint8_t lp;

	size_t len;

	static const unsigned char *input = \
		(const unsigned char *) "\xfe\xad\xbe\xaf";

	Buffer bufr = NULL;

	INIT(HurdLib, Buffer, bufr, ERR(goto done));


	printf("Test number: %d\n", test);
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
