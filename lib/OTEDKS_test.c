/**************************************************************************
 * Copyright (c) Enjellic Systems Development, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include <HurdLib.h>
#include <Buffer.h>
#include <File.h>

#include <IDtoken.h>
#include <SHA256.h>

#include "OTEDKS.h"

#define CCALL(lib,obj,init) lib##_##obj##_##init
#define INIT(lib, obj, var, action) \
	if ( (var = CCALL(lib,obj,Init)()) == NULL ) action


extern int main(int argc, char *argv[])

{
	_Bool debug = false;

	int opt;

	long int lp,
		 id_count = INT_MAX;

	char *idtoken	= NULL,
	     *idkey	= NULL;

	time_t atime = 0,
	       bdate = 0;

	FILE *idfile;

	Buffer tok,
	       key = NULL;

	IDtoken id = NULL;

	OTEDKS otkey = NULL;

	File output = NULL;

	Sha256 sha256 = NULL;


	while ( (opt = getopt(argc, argv, "da:b:i:k:n:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;

			case 'a':
				atime = strtol(optarg, NULL, 10);
				break;
			case 'b':
				bdate = strtol(optarg, NULL, 10);
				break;
			case 'i':
				idtoken = optarg;
				break;
			case 'k':
				idkey = optarg;
				break;
			case 'n':
				id_count = strtol(optarg, NULL, 10);
				if ( id_count == LONG_MIN )
					id_count = LONG_MAX;
				break;
		}

	if ( (idtoken == NULL) || (idkey == NULL) ) {
		fputs("Invalid input, need -i and -k arguements.\n", stderr);
		goto done;
	}


	/* Constructor calls for objects. */;
	INIT(NAAAIM, IDtoken, id, goto done);
	INIT(HurdLib, Buffer, key, goto done);
	INIT(HurdLib, File, output, goto done);
	INIT(NAAAIM, Sha256, sha256, goto done);


	/* Open output file and identity token file. */
	if ( !output->open_rw(output, "OTEDKS.out") ) {
		fputs("Cannot open file.\n", stderr);
		goto done;
	}
	
	if ( (idfile = fopen(idtoken, "r")) == NULL )
		goto done;
	if ( !id->parse(id, idfile) ) {
		fputs("Cannot load identity token.\n", stderr);
		goto done;
	}
	fclose(idfile);


	/* Calculate birthdate and authentication time. */
	if ( atime == 0 )
		atime = time(NULL);
	if ( bdate == 0 )
		bdate = time(NULL);
	if ( debug )
		fprintf(stdout, "Bdate=%ld, Atime=%ld\n", bdate, atime);


	/* Run identity generation cycles. */
	if ( (otkey = NAAAIM_OTEDKS_Init(bdate)) == NULL ) {
		fputs("Cannot initialize key generator.\n", stderr);
		goto done;
	}

	if ( !key->add_hexstring(key, idkey) ) {
		fputs("Cannot create identity key.\n", stderr);
		goto done;
	}

	if ( debug ) {
		fputs("Identity:\n", stdout);
		id->print(id);
	}
	tok = id->get_element(id, IDtoken_id);
	if ( debug ) {
		fputs("\nToken:\n", stdout);
		tok->print(tok);
	}
	
	sha256->add(sha256, id->get_element(id, IDtoken_id));
	sha256->compute(sha256);
	if ( debug ) {
		fputs("\nToken hash:\n", stdout);
		sha256->print(sha256);
		fputc('\n', stdout);
	}

	for (lp= 0; lp < id_count; ++lp) {
		otkey->compute(otkey, atime, key, \
			       sha256->get_Buffer(sha256));
		fprintf(stdout, "Time: %ld\n", atime);
		fputs("Key:  \n", stdout);
		tok = otkey->get_key(otkey);
		tok->print(tok);
		output->write_Buffer(output, tok);
		fputc('\n', stdout);

		otkey->reset(otkey);
		sleep(1);
		atime += 1;
	}


 done:
	WHACK(id);
	WHACK(key);
	WHACK(output);
	WHACK(sha256);
	WHACK(otkey);

	return 0;
}
