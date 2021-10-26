/** \file
 * This file implements the generation of a signed security model map.
 */

/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <RSAkey.h>
#include <Base64.h>


/*
 * Program entry point begins here.
 */

extern int main(int argc, char *argv[])

{
	int opt,
	    retn = 1;

	char *key_file   	= NULL,
	     *model_file	= NULL;

	Buffer bufr	 = NULL,
	       signature = NULL;

	String str = NULL;

	RSAkey rsakey = NULL;

	Base64 encoder = NULL;

	File model = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "k:m:")) != EOF )
		switch ( opt ) {
			case 'k':
				key_file = optarg;
				break;

			case 'm':
				model_file = optarg;
				break;

		}


	/* Verify arguments. */
	if ( key_file == NULL ) {
		fputs("No key specified.\n", stderr);
		goto done;
	}
	if ( model_file == NULL ) {
		fputs("No model specified.\n", stderr);
		goto done;
	}


	/* Load and emit the public signing key. */
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	INIT(NAAAIM, RSAkey, rsakey, ERR(goto done));
	if ( !rsakey->load_private_key(rsakey, key_file, NULL) )
		ERR(goto done);
	if ( !rsakey->get_public_key(rsakey, bufr) )
		ERR(goto done);


	INIT(HurdLib, String, str, ERR(goto done));
	if ( !str->add(str, "key ") )
		ERR(goto done);

	INIT(NAAAIM, Base64, encoder, ERR(goto done));
	if ( !encoder->encode(encoder, bufr, str) )
		ERR(goto done);
	str->print(str);

	bufr->reset(bufr);
	if ( !bufr->add(bufr, (void *) str->get(str), str->size(str) + 1) )
		ERR(goto done);


	/*
	 * Loop through the model file and add each line in the file
	 * to the Buffer object that the signature will be generated
	 * over.
	 */
	INIT(HurdLib, File, model, ERR(goto done));
	if ( !model->open_ro(model, model_file) )
		ERR(goto done);

	str->reset(str);
	while ( model->read_String(model, str) ) {
		if ( !bufr->add(bufr, (void *) str->get(str), \
				str->size(str) + 1) )
			ERR(goto done);
		str->print(str);
		str->reset(str);
	}


	/* Generate the signature over the model. */
	INIT(HurdLib, Buffer, signature, ERR(goto done));
	if ( !rsakey->sign(rsakey, bufr, signature) )
		ERR(goto done);

	str->reset(str);
	if ( !str->add(str, "signature ") )
		ERR(goto done);

	if ( !encoder->encode(encoder, signature, str) )
		ERR(goto done);
	str->print(str);


 done:
	WHACK(bufr);
	WHACK(signature);
	WHACK(rsakey);
	WHACK(str);
	WHACK(encoder);
	WHACK(model);

	return retn;
}
