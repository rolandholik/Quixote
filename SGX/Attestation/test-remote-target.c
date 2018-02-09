/** \file
 * This file contains a test harness for exercising the generation of
 * a remotely verifiable attestation of an enclave.
 */

/**************************************************************************
 * (C)Copyright 2017, IDfusion, LLC. All rights reserved.
 *
 * Please refer to the file named COPYING in the top of the source tree
 * for licensing information.
 **************************************************************************/


#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include <Origin.h>
#include <HurdLib.h>
#include <Buffer.h>
#include <String.h>
#include <File.h>

#include <NAAAIM.h>
#include <RandomBuffer.h>

#include "SGX.h"
#include "SGXenclave.h"
#include "QEenclave.h"
#include "PCEenclave.h"
#include "SGXepid.h"

#include "LocalSource-interface.h"


/** OCALL interface definition. */
struct SGXfusion_ocall0_interface {
	char* str;
} SGXfusion_ocall0;

int ocall0_handler(struct SGXfusion_ocall0_interface *interface)

{
	fprintf(stdout, "%s", interface->str);
	return 0;
}

static const struct OCALL_api ocall_table = {
	1, {ocall0_handler}
};


/**
 * Static public function.
 *
 * This function opens and initializes an enclave whose name and
 * token are specified.
 *
 * \param enclave	The object which will be used to manage the
 *			enclave.
 *
 * \param device	A pointer to a null-terminated character buffer
 *			containing the name of the SGX device used to
 *			issue the control commands to the kernel
 *			driver.
 *
 * \param name		A pointer to a null-terminated character buffer
 *			containing the name of the shared object
 *			file containing the enclave image.
 *
 * \param token		A pointer to a null-terminated character buffer
 *			containing the name of the file containing
 *			the initialization token.
 *
 * \param debug		A boolean value used to indicate whether or
 *			not the debug attribute is to be set on
 *			the enclave.
 *
 * \return	If an error is encountered while initializing the
 *		enclave a false value is returned.  A true value indicates
 *		the enclave has been loaded and initialized.
 */

static _Bool open_enclave(CO(SGXenclave, enclave), CO(char *, device), \
			  CO(char *, name), CO(char *, token), 	       \
			  const _Bool debug)

{
	_Bool retn = false;

	struct SGX_einittoken *einit;

	Buffer bufr = NULL;

	File token_file = NULL;


	INIT(HurdLib, Buffer, bufr, ERR(goto done));
	INIT(HurdLib, File, token_file, ERR(goto done));

	token_file->open_ro(token_file, token);
	if ( !token_file->slurp(token_file, bufr) )
		ERR(goto done);
	einit = (void *) bufr->get(bufr);


	/* Load and initialize the enclave. */
	if ( !enclave->open_enclave(enclave, device, name, debug) )
		ERR(goto done);

	if ( !enclave->create_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->load_enclave(enclave) )
		ERR(goto done);

	if ( !enclave->init_enclave(enclave, einit) )
		ERR(goto done);

	retn = true;


 done:
	WHACK(bufr);
	WHACK(token_file);

	return retn;
}


/* Program entry point. */
extern int main(int argc, char *argv[])

{
	_Bool debug = true;

	char *spid_key	     = NULL,
	     *epid_blob	     = NULL,
	     *sgx_device     = "/dev/isgx",
	     *source_token   = "source.token",
	     *quote_token    = "qe.token",
	     *pce_token	     = "pce.token",
	     *source_enclave = "LocalSource.signed.so";

	int rc,
	    opt,
	    retn = 1;

	struct SGX_targetinfo qe_target_info;

	struct SGX_report __attribute__((aligned(512))) enclave_report;

	struct SGX_psvn pce_psvn;

	struct LocalSource_ecall0_interface source_ecall0;

	Buffer spid = NULL;

	RandomBuffer nonce = NULL;

	QEenclave qe = NULL;

	PCEenclave pce = NULL;

	SGXenclave source = NULL;


	/* Parse and verify arguements. */
	while ( (opt = getopt(argc, argv, "e:q:s:")) != EOF )
		switch ( opt ) {
			case 'e':
				epid_blob = optarg;
				break;
			case 'q':
				quote_token = optarg;
				break;
			case 's':
				spid_key = optarg;
				break;
		}


	/* Verify arguements. */
	if ( epid_blob == NULL ) {
		fputs("No EPID blob specified.\n", stderr);
		goto done;
	}

	if ( spid_key == NULL ) {
		fputs("No SPID specified.\n", stderr);
		goto done;
	}


	/* Load and initialize the source and target enclaves. */
	INIT(NAAAIM, QEenclave, qe, ERR(goto done));
	if ( !qe->open(qe, quote_token) )
		ERR(goto done);

	if ( !qe->get_target_info(qe, &qe_target_info) )
		ERR(goto done);
	fputs("Obtained quoting enclave target information.\n", stderr);


	/* Verify the EPID blob. */
	if ( !qe->load_epid(qe, epid_blob) )
		ERR(goto done);
	fputs("Verified EPID.\n", stdout);


	/* Get the platform security information for the PCE enclave. */
	INIT(NAAAIM, PCEenclave, pce, ERR(goto done));
	if ( !pce->open(pce, pce_token) )
		ERR(goto done);
	pce->get_psvn(pce, &pce_psvn);

	retn = 0;


	/*
	 * Load the source enclave which the quote will be generated
	 * for.  The report will be directed to the quoting enclave.
	 */
	INIT(NAAAIM, SGXenclave, source, ERR(goto done));
	if ( !open_enclave(source, sgx_device, source_enclave, source_token, \
			   debug) )
		ERR(goto done);

	source_ecall0.mode   = 1;
	source_ecall0.target = &qe_target_info;
	source_ecall0.report = &enclave_report;
	if ( !source->boot_slot(source, 0, &ocall_table, &source_ecall0, \
				&rc) ) {
		fprintf(stderr, "Enclave return error: %d\n", rc);
		ERR(goto done);
	}
	if ( !source_ecall0.retn )
		ERR(goto done);
	fputs("Generated quoting enclave report.\n", stdout);


	/*
	 * Convert the SPID into a binary buffer and generate the
	 * nonce to be used.
	 */
	if ( strlen(spid_key) != 32 ) {
		fputs("Invalid SPID size.\n", stderr);
		goto done;
	}

	INIT(HurdLib, Buffer, spid, ERR(goto done));
	if ( !spid->add_hexstring(spid, spid_key) ) {
		fputs("Invalid SPID.\n", stderr);
		goto done;
	}

	INIT(NAAAIM, RandomBuffer, nonce, ERR(goto done));
	if ( !nonce->generate(nonce, 16) ) {
		fputs("Unable to generate nonce.\n", stderr);
		goto done;
	}


 done:
	fputs("Done.\n", stdout);

	WHACK(spid);
	WHACK(nonce);
	WHACK(qe);
	WHACK(pce);
	WHACK(source);


	return retn;

}
