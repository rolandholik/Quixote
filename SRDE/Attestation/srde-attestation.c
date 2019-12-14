/** \file
 * This file implements a utility for management of SRDE remote
 * services.
 */

/**************************************************************************
 * (C)Copyright IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named Documentation/COPYRIGHT in the top of
 * the source tree for copyright and licensing information.
 **************************************************************************/

/* Local defines. */
#if defined(ENCLAVE_DIR)
#define ENCLAVE_DIR	"/opt/IDfusion/lib/enclaves"
#endif
#define ENCLAVE		"Attestation.signed.so"


/* Include files. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>

#include <SRDE.h>
#include <SRDEenclave.h>
#include <SRDEocall.h>
#include <SRDEfusion-ocall.h>
#include <SRDEnaaaim-ocall.h>

#include "LocalSource-interface.h"
#include "LocalTarget-interface.h"
#include "Attestation-interface.h"


/**
 * Private function
 *
 * This function implements the test mode which requests a remote
 * report of the LocalSource unit test enclave.
 *
 * \param token		A pointer to the null-terminated buffer
 *			containing the launch token for the unit
 *			test enclave.
 *
 * \return	A boolean value is used to indicate whether or not
 *		the unit testing succeeded.  A false value
 *		indicates testing failed while a true value indicates
 *		it was successful.
 */

_Bool test_mode(const char *token)

{
	_Bool retn = false;

	char *enclave = "LocalTarget.signed.so";

	int rc;

	struct LocalTarget_ecall3 ecall;

	struct OCALL_api *table;

	SRDEenclave source = NULL;

	SRDEocall ocall = NULL;


	/* Initialize the source enclave. */
	INIT(NAAAIM, SRDEenclave, source, ERR(goto done));
	if ( !source->setup(source, enclave, token, true) )
		ERR(goto done);


	/* Setup OCALL table. */
	INIT(NAAAIM, SRDEocall, ocall, ERR(goto done));

	ocall->add_table(ocall, SRDEfusion_ocall_table);
	ocall->add_table(ocall, SRDEnaaaim_ocall_table);

	if ( !ocall->get_table(ocall, &table) )
		ERR(goto done);


	/* Invoke the attestation testing ECALL. */
	fputs("srde-attestation: Testing remote attestation.\n", stdout);

	if ( !source->boot_slot(source, 3, table, &ecall, &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !ecall.retn )
		ERR(goto done);


 done:
	WHACK(source);
	WHACK(ocall);

	return retn;
}


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	_Bool debug_enclave = true;

	char *key	   = NULL,
	     *token	   = SGX_TOKEN_DIRECTORY"/Attestation.token",
	     *enclave_name = ENCLAVE_NAME;

	int opt,
	    rc,
	    retn = 1;

	enum {
		none,
		provision,
		test
	} mode = none;

	struct OCALL_api *ocall_table;

	struct Attestation_ecall0 ecall0;

	Buffer bufr = NULL;

	SRDEenclave enclave = NULL;

	SRDEocall ocall = NULL;

	File keyfile = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "PTk:t:")) != EOF )
		switch ( opt ) {
			case 'P':
				mode = provision;
				break;
			case 'T':
				mode = test;
				break;

			case 'k':
				key = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}


	/* Verify arguements. */
	if ( mode == none ) {
		fputs("No mode specified.\n", stderr);
		goto done;
	}

	if ( (mode == provision) && (key == NULL) ) {
		fputs("No authentication key specified.\n", stderr);
		goto done;
	}


	/* Execute test mode. */
	if ( mode == test ) {
		if ( test_mode(token) )
			retn = 0;
		goto done;
	}


	/* Initialize the provisioning enclave. */
	INIT(NAAAIM, SRDEenclave, enclave, ERR(goto done));
	if ( !enclave->setup(enclave, enclave_name, token, debug_enclave) )
		ERR(goto done);


	/* Setup OCALL table. */
	INIT(NAAAIM, SRDEocall, ocall, ERR(goto done));

	ocall->add_table(ocall, SRDEfusion_ocall_table);
	ocall->add_table(ocall, SRDEnaaaim_ocall_table);

	if ( !ocall->get_table(ocall, &ocall_table) )
		ERR(goto done);


	/* Load the private key. */
	INIT(HurdLib, File, keyfile, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	if ( !keyfile->open_ro(keyfile, key) )
			ERR(goto done);
	if ( !keyfile->slurp(keyfile, bufr) )
		ERR(goto done);

	ecall0.retn	    = false;
	ecall0.current_time = time(NULL);

	ecall0.key_size = bufr->size(bufr);
	ecall0.key	= bufr->get(bufr);

	if ( !enclave->boot_slot(enclave, 0, ocall_table, &ecall0, \
				 &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}

	if ( !ecall0.retn ) {
		fputs("Internal enclave error.\n", stderr);
		goto done;
	}

	retn = 0;


 done:
	WHACK(bufr);
	WHACK(enclave);
	WHACK(ocall);
	WHACK(keyfile);

	return retn;
}
