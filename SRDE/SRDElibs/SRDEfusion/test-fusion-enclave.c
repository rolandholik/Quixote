/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include <sys/types.h>

#include <sgx_tcrypto.h>

#include "test-fusion-interface.h"

#include "HurdLib.h"
#include "Buffer.h"
#include "String.h"
#include "File.h"


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


static void test_three(void)

{
	char inbufr[100];


	fputs("Test number: 3\n", stdout);

	fputs("\nInput:\n", stdout);

	memset(inbufr, '\0', sizeof(inbufr));
	if ( fgets(inbufr, sizeof(inbufr), stdin) == NULL )
		fputs("NULL return\n", stdout);

	fprintf(stdout, "\nInput: '%s'\n", inbufr);

	return;
}

static void test_four(void)

{
	char *msg = "Test file output.\n";

	Buffer bufr = NULL;

	File file = NULL;


	fputs("Test number: 4\n", stdout);

	fputs("Initializing file.\n", stdout);
	INIT(HurdLib, File, file, ERR(goto done));

	fputs("Testing file read-write open.\n", stdout);
	if ( !file->open_rw(file, "test.file") ) {
		fputs("Error opening file.\n", stdout);
		goto done;
	}

	fputs("Testing file write.\n", stdout);
	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	if ( !bufr->add(bufr, (void *) msg, strlen(msg)+1) )
		ERR(goto done);
	file->write_Buffer(file, bufr);

	fputs("Closing file.\n", stdout);
	WHACK(file);

	fputs("\nTesting file read-only open.\n", stdout);
	INIT(HurdLib, File, file, ERR(goto done));
	if ( !file->open_ro(file, "test.file") ) {
		fputs("Error opening file.\n", stdout);
		goto done;
	}

	fputs("\nTesting file slurp.\n", stdout);
	bufr->reset(bufr);
	if ( !file->slurp(file, bufr) ) {
		fputs("Error slurping file.\n", stdout);
		goto done;
	}
	bufr->hprint(bufr);


 done:
	WHACK(bufr);
	WHACK(file);

	return;
}


static void test_lost_object(void)

{
	Buffer bufr = NULL;

	fputs("Test number: 100\n", stdout);

	fputs("Allocating lost Buffer object.\n", stdout);
	INIT(HurdLib, Buffer, bufr, return);

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
		case 3:
			test_three();
			break;
		case 4:
			test_four();
			break;
		case 100:
			test_lost_object();
			break;
		default:
			fputs("Invalid test.\n", stderr);
			break;
	}

	fprintf(stdout, "End test: %d\n", test);
	return;
}
