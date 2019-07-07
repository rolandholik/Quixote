/** \file
 * This file contains the implementation of a utility which loads
 * and initializes an SGX enclave.  This utility is primarily useful
 * for testing the IDfusion SGX runtime infrastructure.  It also
 * provides a framework for generating extensive diagnostic information
 * on the enclave loading process.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Definitions local to this file. */
#define PGM "sgx-load"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>

#include <String.h>
#include <Buffer.h>
#include <File.h>

#include "NAAAIM.h"
#include "SGX.h"
#include "SGXenclave.h"


/**
 * Internal public function.
 *
 * This method implements outputting of an error message and status
 * information on how to run the utility.
 *
 * \param err	A pointer to a null-terminated buffer holding the
 *		error message to be output.
 *
 * \return	No return value is defined.
 */

static void usage(char *err)

{
	fprintf(stdout, "%s: SGX enclave loader.\n", PGM);
	fprintf(stdout, "%s: (C)IDfusion, LLC\n", PGM);

	if ( err != NULL )
		fprintf(stdout, "\n%s", err);

	fputc('\n', stdout);
	fputs("Usage:\n", stdout);
	fputs("\t-d:\tEnable debug mode.\n", stdout);
	fputs("\t-p:\tGenerate token for a non-debug enclave.\n\n", stdout);

	fputs("\t-e:\tEnclave to generate token for.\n", stdout);
	fputs("\t-n:\tSGX device node.\n\t\t\tdefault = /dev/isgx\n", stdout);
	fputs("\t-t:\tThe file containing the initialization token\n\n", \
	      stdout);

	return;
}


/* Main program starts here. */

extern int main(int argc, char *argv[])

{
	_Bool debug	    = false,
	      debug_enclave = true;

	char *token	   = NULL,
	     *sgx_device   = "/dev/isgx",
	     *enclave_name = NULL;

	int opt,
	    retn = 1;

	struct SGX_einittoken *einit = NULL;

	SGXenclave enclave = NULL;

	Buffer bufr = NULL;

	File token_file = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "Ndpe:n:t:")) != EOF )
		switch ( opt ) {
			case 'd':
				debug = true;
				break;
			case 'p':
				debug_enclave = false;
				break;

			case 'e':
				enclave_name = optarg;
				break;
			case 'n':
				sgx_device = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}

	if ( enclave_name == NULL ) {
		usage("No enclave name specifed.\n");
		goto done;
	}


	/* Load the launch token. */
	if ( (token != NULL) && (token[0] != '\0') ) {

		INIT(HurdLib, Buffer, bufr, ERR(goto done));
		INIT(HurdLib, File, token_file, ERR(goto done));
		if ( debug )
			fprintf(stdout, "Loading enclave token: %s\n\n", \
				token);

		token_file->open_ro(token_file, token);
		if ( !token_file->slurp(token_file, bufr) )
			ERR(goto done);
		einit = (void *) bufr->get(bufr);
	}


	/* Load and initialize the enclave. */
	INIT(NAAAIM, SGXenclave, enclave, ERR(goto done));

	if ( debug ) {
		fprintf(stdout, "Loading enclave: %s\n\n", enclave_name);
		enclave->debug(enclave, true);
	}

	if ( !enclave->open_enclave(enclave, sgx_device, enclave_name, \
				    debug_enclave) )
		ERR(goto done);
	fputs("Enclave opened.\n", stdout);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);
	fputs("Enclave created.\n", stdout);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);
	fputs("Enclave loaded.\n", stdout);

	if ( (token == NULL) || (token[0] == '\0') )
		fputs("Non-token initialization requested.\n", stdout);
	if ( !enclave->init_enclave(enclave, einit) )
		ERR(goto done);
	fputs("Enclave initialized.\n", stdout);

	fputs("OK\n", stdout);
	retn = 0;


 done:
	WHACK(bufr);
	WHACK(token_file);
	WHACK(enclave);

	return retn;

}
