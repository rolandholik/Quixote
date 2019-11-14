/** \file
 * This file contains a test harness for exercising the functionality
 * of the enclave based PossumPipe object operating in authentication
 * mode 2 which uses a public/private keypair for authenticating the
 * setup of a PossumPipe connection.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/


/* Program name and associated enclave. */
#define PGM "test-Possum2"
#define ENCLAVE PGM".signed.so"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <Origin.h>
#include <HurdLib.h>
#include <String.h>
#include <Buffer.h>
#include <File.h>

#include <NAAAIM.h>
#include <Duct.h>
#include <PossumPipe.h>
#include <IDtoken.h>

#include <SRDE.h>
#include <SRDEenclave.h>
#include <SRDEquote.h>
#include <SRDEocall.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "test-Possum2-interface.h"


/**
 * Program entry point.
 *
 * The following arguements are processed:
 *
 *	-S:	Used to specify that the utility is to be run in
 *		server mode.
 *
 *	-C:	Used to specify that the utility is to run in client
 *		mode.
 *
 *	-d:	By default the debug attribute is set for the enclave.
 *		This option toggles that option.
 *
 *	-e:	The enclave which is to be executed.
 *
 *	-t:	The file containing the EINITTOKEN for this processor.
 *
 *	-k:	Used to specify the name of the file containing the
 *		authentication key.  In server mode this will be a
 *		file containing a public key while in client mode the
 *		file will be expected to contain a private key.
 */

extern int main(int argc, char *argv[])

{
	_Bool debug_mode    = false,
	      debug_enclave = true;

	char *keyfile	   = NULL,
	     *spidfile	   = SPID_FILENAME,
	     *token	   = SGX_TOKEN_DIRECTORY"/test-Possum2.token",
	     *hostname	   = "localhost",
	     *enclave_name = ENCLAVE_NAME;

	int opt,
	    rc,
	    retn = 1;

	enum {none, client, server, measure} Mode = none;

	Buffer bufr	= NULL,
	       keybufr	= NULL;

	String spid = NULL;

	File infile = NULL;

	SRDEenclave enclave = NULL;

	SRDEocall ocall = NULL;

	struct OCALL_api *ocall_table;

	struct Possum2_ecall0 ecall0;

	struct Possum2_ecall1 ecall1;

	struct Possum2_ecall2 ecall2;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "CSdph:k:s:t:")) != EOF )
		switch ( opt ) {
			case 'C':
				Mode = client;
				break;
			case 'S':
				Mode = server;
				break;

			case 'd':
				debug_mode = true;
				break;
			case 'p':
				debug_enclave = false;
				break;

			case 'h':
				hostname = optarg;
				break;
			case 'k':
				keyfile = optarg;
				break;
			case 's':
				spidfile = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}


	/* Validate that required arguements are present. */
	if ( Mode == none ) {
		fputs("No mode specified.\n", stderr);
		goto done;
	}


	/* Build the OCALL dispatch table. */
	INIT(NAAAIM, SRDEocall, ocall, ERR(goto done));

	ocall->add_table(ocall, SRDEfusion_ocall_table);
	ocall->add_table(ocall, SRDEnaaaim_ocall_table);

	if ( !ocall->get_table(ocall, &ocall_table) )
		ERR(goto done);


	/* Output header. */
	fprintf(stdout, "%s: IDfusion SGX PossumPipe2 test utility.\n", PGM);
	fprintf(stdout, "%s: (C)Copyright 2019, IDfusion, LLC. All rights "
		"reserved.\n\n", PGM);

	if ( keyfile == NULL ) {
		fputs("No identifier key specifed.\n", stderr);
		goto done;
	}


	/* Load the identity key. */
	INIT(HurdLib, Buffer, keybufr, goto done);
	INIT(HurdLib, File, infile, goto done);

	infile->open_ro(infile, keyfile);
	if ( !infile->slurp(infile, keybufr) ) {
		fputs("Cannot read the identity key.\n", stderr);
		goto done;
	}


	/* Load the enclave. */
	INIT(NAAAIM, SRDEenclave, enclave, ERR(goto done));
	if ( !enclave->setup(enclave, enclave_name, token, debug_enclave) )
		ERR(goto done);


	/* Test server mode. */
	if ( Mode == server ) {
		/* Setup the SPID. */
		INIT(HurdLib, String, spid, ERR(goto done));

		infile->reset(infile);
		if ( !infile->open_ro(infile, spidfile) )
			ERR(goto done);
		if ( !infile->read_String(infile, spid) )
			ERR(goto done);

		if ( spid->size(spid) != 32 ) {
			fputs("Invalid SPID size: ", stdout);
			spid->print(spid);
			goto done;
		}


		/* Load the verifier key. */
		memset(&ecall2, '\0', sizeof(struct Possum2_ecall2));
		ecall2.key	= keybufr->get(keybufr);
		ecall2.key_size = keybufr->size(keybufr);

		if ( !enclave->boot_slot(enclave, 2, ocall_table, \
					 &ecall2, &rc) ) {
			fprintf(stderr, "Ecall 2 returned: %d\n", rc);
			goto done;
		}


		/* Execute server mode. */
		memset(&ecall0, '\0', sizeof(struct Possum2_ecall0));

		ecall0.debug_mode   = debug_mode;
		ecall0.port	    = 11990;
		ecall0.current_time = time(NULL);

		ecall0.spid	 = spid->get(spid);
		ecall0.spid_size = spid->size(spid) + 1;

		if ( !enclave->boot_slot(enclave, 0, ocall_table, \
					 &ecall0, &rc) ) {
			fprintf(stderr, "Ecall 0 returned: %d\n", rc);
			goto done;
		}
	}


	/* Test client mode. */
	if ( Mode == client ) {
		memset(&ecall1, '\0', sizeof(struct Possum2_ecall1));

		ecall1.debug_mode    = debug_mode;
		ecall1.port	     = 11990;
		ecall1.current_time  = time(NULL);

		ecall1.hostname	     = hostname;
		ecall1.hostname_size = strlen(hostname) + 1;

		ecall1.key	     = keybufr->get(keybufr);
		ecall1.key_size	     = keybufr->size(keybufr);

		if ( !enclave->boot_slot(enclave, 1, ocall_table, \
					 &ecall1, &rc) ) {
			fprintf(stderr, "Ecall 1 returned: %d\n", rc);
			goto done;
		}
		fputs("Completed client mode.\n", stdout);
	}

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(keybufr);
	WHACK(spid);
	WHACK(infile);
	WHACK(enclave);
	WHACK(ocall);

	return retn;

}
