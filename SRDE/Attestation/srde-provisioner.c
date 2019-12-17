/** \file
 * This file implements a driver for the Provisioner enclave that
 * supports the provisioning of remote attestation credentials to an
 * Attestation enclave on a client platform.
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
#define ENCLAVE		"Provisioner.signed.so"


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

#include "Provisioner-interface.h"


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	_Bool debug_enclave = true;

	char *spid	   = NULL,
	     *apikey	   = NULL,
	     *token	   = SGX_TOKEN_DIRECTORY"/Provisioner.token",
	     *enclave_name = ENCLAVE_NAME;

	int opt,
	    rc,
	    retn = 1;

	unsigned int lp,
		     key_cnt = 0;

	char *public_keys[5];

	struct OCALL_api *ocall_table;

	struct Provisioner_ecall0 ecall0;

	struct Provisioner_ecall1 ecall1;

	SRDEenclave enclave = NULL;

	SRDEocall ocall = NULL;

	Buffer bufr = NULL;

	String keystr = NULL;

	File keyfile = NULL;


	/* Parse and verify arguements. */
	memset(public_keys, '\0', sizeof(public_keys));

	while ( (opt = getopt(argc, argv, "k:p:s:t:")) != EOF )
		switch ( opt ) {
			case 'k':
				apikey = optarg;
				break;
			case 'p':
				if ( key_cnt > 4 ) {
					fputs("Too many public keys.\n", \
					      stderr);
					goto done;
				}
				public_keys[key_cnt++] = optarg;
				break;
			case 's':
				spid = optarg;
				break;
			case 't':
				token = optarg;
				break;
		}


	/* Verify arguements. */
	if ( spid == NULL ) {
		fputs("No SPID specified.\n", stderr);
		goto done;
	}

	if ( apikey == NULL ) {
		fputs("No APIkey specified.\n", stderr);
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


	/* Load the private keys. */
	fputs("srde-provisioner: Starting credential provisioner.\n", stdout);
	fputs("Loading authenticating keys:", stdout);

	INIT(HurdLib, File, keyfile, ERR(goto done));
	INIT(HurdLib, Buffer, bufr, ERR(goto done));

	for (lp= 0; lp < key_cnt; ++lp) {
		fprintf(stdout, "\n\tKey: %s\n", public_keys[lp]);
		if ( !keyfile->open_ro(keyfile, public_keys[lp]) )
			ERR(goto done);
		if ( !keyfile->slurp(keyfile, bufr) )
			ERR(goto done);

		ecall0.retn	= false;
		ecall0.key_size = bufr->size(bufr);
		ecall0.key	= (char *) bufr->get(bufr);

		if ( !enclave->boot_slot(enclave, 0, ocall_table, &ecall0, \
					 &rc) ) {
			fprintf(stderr, "Enclave return error: %d\n", rc);
			ERR(goto done);
		}

		if ( !ecall0.retn ) {
			fputs("Internal enclave error.\n", stderr);
			goto done;
		}


		keyfile->reset(keyfile);
		bufr->reset(bufr);
	}


	/* Start the provisioner. */
	INIT(HurdLib, String, keystr, ERR(goto done));

	ecall1.retn	    = false;
	ecall1.current_time = time(NULL);

	keyfile->reset(keyfile);
	if ( !keyfile->open_ro(keyfile, spid) )
		ERR(goto done);
	if ( !keyfile->read_String(keyfile, keystr) )
		ERR(goto done);
	strcpy(ecall1.spid, keystr->get(keystr));

	keystr->reset(keystr);
	keyfile->reset(keyfile);
	if ( !keyfile->open_ro(keyfile, apikey) )
		ERR(goto done);
	if ( !keyfile->read_String(keyfile, keystr) )
		ERR(goto done);
	strcpy(ecall1.apikey, keystr->get(keystr));

	if ( !enclave->boot_slot(enclave, 1, ocall_table, &ecall1, &rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}

	if ( !ecall1.retn ) {
		fputs("Internal enclave error.\n", stderr);
		ERR(goto done);
	}

	retn = 0;


 done:
	WHACK(enclave);
	WHACK(ocall);
	WHACK(bufr);
	WHACK(keystr);
	WHACK(keyfile);

	return retn;
}
